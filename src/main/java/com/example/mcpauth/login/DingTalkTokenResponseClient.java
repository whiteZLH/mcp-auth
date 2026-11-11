package com.example.mcpauth.login;

import java.time.Duration;
import java.util.LinkedHashMap;
import java.util.Map;

import org.springframework.http.MediaType;
import org.springframework.security.oauth2.client.endpoint.OAuth2AccessTokenResponseClient;
import org.springframework.security.oauth2.client.endpoint.OAuth2AuthorizationCodeGrantRequest;
import org.springframework.security.oauth2.core.OAuth2AccessToken;
import org.springframework.security.oauth2.core.OAuth2AuthenticationException;
import org.springframework.security.oauth2.core.OAuth2Error;
import org.springframework.security.oauth2.core.OAuth2ErrorCodes;
import org.springframework.security.oauth2.core.endpoint.OAuth2AccessTokenResponse;
import org.springframework.web.client.RestClient;
import org.springframework.web.client.RestClientException;

/**
 * 用钉钉授权码换取用户访问令牌。
 *
 * <p>Spring 的 {@code DefaultAuthorizationCodeTokenResponseClient} 会以表单形式提交
 * {@code client_id}/{@code client_secret}/{@code grant_type}/{@code code}。钉钉要求 JSON 请求体，
 * 字段为 {@code clientId}/{@code clientSecret}/{@code code}/{@code grantType}，并返回
 * {@code accessToken}/{@code expireIn}/{@code refreshToken}/{@code corpId} —— 没有 {@code token_type}。
 * 因此改用这个适配器而不是默认客户端。
 */
public final class DingTalkTokenResponseClient implements OAuth2AccessTokenResponseClient<OAuth2AuthorizationCodeGrantRequest> {

    private final RestClient restClient;
    private final String tokenUri;

    public DingTalkTokenResponseClient(RestClient restClient, String tokenUri) {
        this.restClient = restClient;
        this.tokenUri = tokenUri;
    }

    @Override
    public OAuth2AccessTokenResponse getTokenResponse(OAuth2AuthorizationCodeGrantRequest grantRequest) {
        String code = grantRequest.getAuthorizationExchange().getAuthorizationResponse().getCode();
        var registration = grantRequest.getClientRegistration();

        Map<String, Object> request = new LinkedHashMap<>();
        request.put("clientId", registration.getClientId());
        request.put("clientSecret", registration.getClientSecret());
        request.put("code", code);
        request.put("grantType", "authorization_code");

        Map<?, ?> response;
        try {
            response = this.restClient.post()
                    .uri(this.tokenUri)
                    .contentType(MediaType.APPLICATION_JSON)
                    .body(request)
                    .retrieve()
                    .body(Map.class);
        }
        catch (RestClientException ex) {
            throw new OAuth2AuthenticationException(new OAuth2Error(OAuth2ErrorCodes.INVALID_TOKEN,
                    "DingTalk token exchange failed: " + ex.getMessage(), null), ex);
        }

        if (response == null || response.get("accessToken") == null) {
            throw new OAuth2AuthenticationException(new OAuth2Error(OAuth2ErrorCodes.INVALID_TOKEN,
                    "DingTalk token exchange returned no accessToken", null));
        }

        OAuth2AccessTokenResponse.Builder builder = OAuth2AccessTokenResponse
                .withToken(String.valueOf(response.get("accessToken")))
                // 钉钉没有 token_type 字段；它签发的都是 bearer 令牌。
                .tokenType(OAuth2AccessToken.TokenType.BEARER)
                .scopes(registration.getScopes());

        Object expireIn = response.get("expireIn");
        if (expireIn instanceof Number seconds && seconds.longValue() > 0) {
            builder.expiresIn(seconds.longValue());
        }
        Object refreshToken = response.get("refreshToken");
        if (refreshToken != null && !String.valueOf(refreshToken).isBlank()) {
            builder.refreshToken(String.valueOf(refreshToken));
        }
        Object corpId = response.get("corpId");
        if (corpId != null) {
            builder.additionalParameters(Map.of("corpId", String.valueOf(corpId)));
        }
        return builder.build();
    }
}
