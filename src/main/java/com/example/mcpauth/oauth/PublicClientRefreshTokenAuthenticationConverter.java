package com.example.mcpauth.oauth;

import jakarta.servlet.http.HttpServletRequest;

import org.springframework.security.core.Authentication;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.core.ClientAuthenticationMethod;
import org.springframework.security.oauth2.core.endpoint.OAuth2ParameterNames;
import org.springframework.security.oauth2.server.authorization.authentication.OAuth2ClientAuthenticationToken;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClientRepository;
import org.springframework.security.web.authentication.AuthenticationConverter;
import org.springframework.util.StringUtils;

/**
 * 在 {@code refresh_token} 授权上仅凭 {@code client_id} 认证公开客户端。
 *
 * <p>Spring Security 内置的公开客户端转换器（{@code PublicClientAuthenticationConverter}）
 * 只接受同时带有 {@code code_verifier} 的请求，也就是授权码换票。刷新请求没有这个参数，
 * 于是公开客户端永远无法兑换它的刷新令牌：令牌端点会返回 {@code invalid_client}。
 *
 * <p>RFC 6749 §6 在刷新时只要求识别出客户端，而公开客户端本来也没有可用于证明身份的密钥。
 * 因此本转换器返回的令牌其凭据为 {@link PublicClientRefreshTokenAuthenticationProvider#REFRESH_GRANT_MARKER}，
 * 这样这条路径既不会与校验 PKCE 的路径混淆，也不会把它短路掉。
 */
public final class PublicClientRefreshTokenAuthenticationConverter implements AuthenticationConverter {

    private final RegisteredClientRepository registeredClients;

    public PublicClientRefreshTokenAuthenticationConverter(RegisteredClientRepository registeredClients) {
        this.registeredClients = registeredClients;
    }

    @Override
    public Authentication convert(HttpServletRequest request) {
        if (!"POST".equals(request.getMethod())) {
            return null;
        }
        if (!AuthorizationGrantType.REFRESH_TOKEN.getValue().equals(request.getParameter(OAuth2ParameterNames.GRANT_TYPE))) {
            return null;
        }
        String clientId = request.getParameter(OAuth2ParameterNames.CLIENT_ID);
        if (!StringUtils.hasText(clientId)) {
            return null;
        }
        RegisteredClient client = this.registeredClients.findByClientId(clientId);
        if (client == null || !client.getClientAuthenticationMethods().contains(ClientAuthenticationMethod.NONE)) {
            // 交给默认转换器去产生正确的 invalid_client 错误。
            return null;
        }
        return new OAuth2ClientAuthenticationToken(client, ClientAuthenticationMethod.NONE,
                PublicClientRefreshTokenAuthenticationProvider.REFRESH_GRANT_MARKER);
    }
}
