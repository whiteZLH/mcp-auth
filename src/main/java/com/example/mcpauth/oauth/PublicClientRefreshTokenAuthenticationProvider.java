package com.example.mcpauth.oauth;

import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.oauth2.core.ClientAuthenticationMethod;
import org.springframework.security.oauth2.server.authorization.authentication.OAuth2ClientAuthenticationToken;

/**
 * 把 {@code refresh_token} 请求的客户端标记为已认证。
 *
 * <p>只接受由 {@link PublicClientRefreshTokenAuthenticationConverter} 产生的令牌，
 * 通过其标记凭据来识别。这个标记很关键：默认的公开客户端提供方支持所有
 * {@code ClientAuthenticationMethod.NONE} 令牌，并在处理时校验 PKCE 的
 * {@code code_verifier} —— 如果在这里也匹配这些令牌，就等于允许在没有 PKCE 的情况下兑换授权码。
 */
public final class PublicClientRefreshTokenAuthenticationProvider implements AuthenticationProvider {

    static final Object REFRESH_GRANT_MARKER = new Object();

    @Override
    public Authentication authenticate(Authentication authentication) throws AuthenticationException {
        OAuth2ClientAuthenticationToken clientAuthentication = (OAuth2ClientAuthenticationToken) authentication;

        // 其他任何情况（尤其是授权码换票时带 code_verifier 的令牌）都必须落到默认提供方，
        // 所以这里返回 null 是刻意为之。
        if (clientAuthentication.getCredentials() != REFRESH_GRANT_MARKER) {
            return null;
        }
        if (clientAuthentication.isAuthenticated()) {
            return clientAuthentication;
        }
        // 重建为已认证状态；三参数构造函数会把 authenticated 设为 true。
        return new OAuth2ClientAuthenticationToken(clientAuthentication.getRegisteredClient(),
                ClientAuthenticationMethod.NONE, null);
    }

    @Override
    public boolean supports(Class<?> authentication) {
        return OAuth2ClientAuthenticationToken.class.isAssignableFrom(authentication);
    }
}
