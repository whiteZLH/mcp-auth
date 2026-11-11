package com.example.mcpauth.oauth;

import java.time.Instant;

import org.springframework.security.oauth2.core.OAuth2RefreshToken;
import org.springframework.security.oauth2.server.authorization.OAuth2Authorization;
import org.springframework.security.oauth2.server.authorization.OAuth2AuthorizationService;

/**
 * 记住某个授权首次签发刷新令牌的时间。
 *
 * <p>之所以需要它，是因为刷新令牌轮换会替换令牌：第一次轮换之后，授权里只剩下最新的刷新令牌，
 * 其 {@code issuedAt} 是轮换时刻。最初的签发时间就此丢失，也就失去了限制总寿命的可能。
 *
 * <p>该时间戳作为一个普通的 {@link OAuth2Authorization} 属性保存，它能挺过轮换，因为刷新令牌
 * 提供方通过 {@code OAuth2Authorization.from(existingAuthorization)} 重建授权并保留属性。
 */
public final class FirstIssuanceTrackingAuthorizationService implements OAuth2AuthorizationService {

    /** 用于在轮换之间携带首次刷新令牌签发时间的属性名。 */
    public static final String FIRST_REFRESH_ISSUED_AT = "mcp-auth.first-refresh-issued-at";

    private final OAuth2AuthorizationService delegate;

    public FirstIssuanceTrackingAuthorizationService(OAuth2AuthorizationService delegate) {
        this.delegate = delegate;
    }

    @Override
    public void save(OAuth2Authorization authorization) {
        this.delegate.save(stampIfFirstIssuance(authorization));
    }

    @Override
    public void remove(OAuth2Authorization authorization) {
        this.delegate.remove(authorization);
    }

    @Override
    public OAuth2Authorization findById(String id) {
        return this.delegate.findById(id);
    }

    @Override
    public OAuth2Authorization findByToken(String token, org.springframework.security.oauth2.server.authorization.OAuth2TokenType tokenType) {
        return this.delegate.findByToken(token, tokenType);
    }

    static OAuth2Authorization stampIfFirstIssuance(OAuth2Authorization authorization) {
        if (authorization.getRefreshToken() == null || authorization.getAttribute(FIRST_REFRESH_ISSUED_AT) != null) {
            return authorization;
        }
        OAuth2RefreshToken refreshToken = authorization.getRefreshToken().getToken();
        Instant firstIssuedAt = refreshToken.getIssuedAt() != null ? refreshToken.getIssuedAt() : Instant.now();
        return OAuth2Authorization.from(authorization)
                .attribute(FIRST_REFRESH_ISSUED_AT, firstIssuedAt)
                .build();
    }
}
