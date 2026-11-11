package com.example.mcpauth.oauth;

import java.time.Duration;
import java.time.Instant;

import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.oauth2.core.OAuth2AuthenticationException;
import org.springframework.security.oauth2.core.OAuth2Error;
import org.springframework.security.oauth2.core.OAuth2ErrorCodes;
import org.springframework.security.oauth2.server.authorization.OAuth2Authorization;
import org.springframework.security.oauth2.server.authorization.OAuth2AuthorizationService;
import org.springframework.security.oauth2.server.authorization.OAuth2TokenType;
import org.springframework.security.oauth2.server.authorization.authentication.OAuth2RefreshTokenAuthenticationToken;

/**
 * 为刷新令牌链条的总寿命设定上限。
 *
 * <p>在 {@code reuseRefreshTokens(false)} 下，每次刷新都会签发一个新令牌，其过期时间按当前时间计算，
 * 因此持续刷新的客户端永远不会过期——凭据实际是永生的。这不该是"30 天会话"的含义。
 *
 * <p>一旦首次签发时间加上 {@code maxLifetime} 已过，本提供方就拒绝刷新。错误为 {@code invalid_grant}
 * （RFC 6749 §5.2），这是客户端应当据以行动、让用户重新走一遍授权的唯一信号。
 */
public final class AbsoluteLifetimeRefreshTokenAuthenticationProvider implements AuthenticationProvider {

    private final AuthenticationProvider delegate;
    private final OAuth2AuthorizationService authorizationService;
    private final Duration maxLifetime;

    public AbsoluteLifetimeRefreshTokenAuthenticationProvider(AuthenticationProvider delegate,
            OAuth2AuthorizationService authorizationService, Duration maxLifetime) {
        this.delegate = delegate;
        this.authorizationService = authorizationService;
        this.maxLifetime = maxLifetime;
    }

    @Override
    public Authentication authenticate(Authentication authentication) throws AuthenticationException {
        if (!(authentication instanceof OAuth2RefreshTokenAuthenticationToken refreshRequest)) {
            return this.delegate.authenticate(authentication);
        }
        OAuth2Authorization authorization = this.authorizationService
                .findByToken(refreshRequest.getRefreshToken(), OAuth2TokenType.REFRESH_TOKEN);
        if (authorization != null && exceedsAbsoluteLifetime(authorization, this.maxLifetime, Instant.now())) {
            throw new OAuth2AuthenticationException(new OAuth2Error(OAuth2ErrorCodes.INVALID_GRANT,
                    "The refresh token chain exceeded its maximum lifetime of " + this.maxLifetime
                            + "; the user has to authorize again",
                    null));
        }
        return this.delegate.authenticate(authentication);
    }

    @Override
    public boolean supports(Class<?> authentication) {
        return this.delegate.supports(authentication);
    }

    /**
     * 当该授权的首次签发时间距今已超过 {@code maxLifetime} 时返回 true。
     *
     * <p>属性缺失时（本检查出现之前创建的授权）回退到当前刷新令牌的 {@code issuedAt}，
     * 这样退化为"第一次轮换时不设上限"，而不是一律拒绝。
     */
    static boolean exceedsAbsoluteLifetime(OAuth2Authorization authorization, Duration maxLifetime, Instant now) {
        if (maxLifetime == null || maxLifetime.isZero() || maxLifetime.isNegative()) {
            return false;
        }
        Instant firstIssuedAt = authorization
                .getAttribute(FirstIssuanceTrackingAuthorizationService.FIRST_REFRESH_ISSUED_AT);
        if (firstIssuedAt == null && authorization.getRefreshToken() != null) {
            firstIssuedAt = authorization.getRefreshToken().getToken().getIssuedAt();
        }
        return firstIssuedAt != null && firstIssuedAt.plus(maxLifetime).isBefore(now);
    }
}
