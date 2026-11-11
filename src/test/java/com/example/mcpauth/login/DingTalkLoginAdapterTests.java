package com.example.mcpauth.login;

import java.io.IOException;
import java.net.InetSocketAddress;
import java.nio.charset.StandardCharsets;
import java.time.Duration;
import java.util.concurrent.atomic.AtomicReference;

import com.sun.net.httpserver.HttpExchange;
import com.sun.net.httpserver.HttpServer;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import org.springframework.security.oauth2.client.endpoint.OAuth2AuthorizationCodeGrantRequest;
import org.springframework.security.oauth2.client.registration.ClientRegistration;
import org.springframework.security.oauth2.client.userinfo.OAuth2UserRequest;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.core.ClientAuthenticationMethod;
import org.springframework.security.oauth2.core.OAuth2AccessToken;
import org.springframework.security.oauth2.core.endpoint.OAuth2AuthorizationExchange;
import org.springframework.security.oauth2.core.endpoint.OAuth2AuthorizationRequest;
import org.springframework.security.oauth2.core.endpoint.OAuth2AuthorizationResponse;
import org.springframework.security.oauth2.core.user.OAuth2User;
import org.springframework.web.client.RestClient;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * 证明钉钉适配器说的是钉钉的“方言”，而无需任何钉钉账号：由本地桩服务器扮演
 * {@code api.dingtalk.com} 的角色。
 *
 * <p>这里断言的，恰恰是有人试图复用 Spring 标准客户端时会出问题的地方：用 JSON 而非表单编码，
 * 用 {@code clientId}/{@code grantType} 而非 {@code client_id}/{@code grant_type}，
 * 以及用 {@code x-acs-dingtalk-access-token} 而非 {@code Authorization: Bearer}。
 */
class DingTalkLoginAdapterTests {

    private HttpServer server;
    private String baseUrl;

    private final AtomicReference<String> lastMethod = new AtomicReference<>();
    private final AtomicReference<String> lastContentType = new AtomicReference<>();
    private final AtomicReference<String> lastBody = new AtomicReference<>();
    private final AtomicReference<String> lastDingTalkTokenHeader = new AtomicReference<>();

    @BeforeEach
    void startStubServer() throws IOException {
        this.server = HttpServer.create(new InetSocketAddress("127.0.0.1", 0), 0);
        this.baseUrl = "http://127.0.0.1:" + this.server.getAddress().getPort();

        this.server.createContext("/v1.0/oauth2/userAccessToken", exchange -> {
            this.lastMethod.set(exchange.getRequestMethod());
            this.lastContentType.set(exchange.getRequestHeaders().getFirst("Content-Type"));
            this.lastBody.set(new String(exchange.getRequestBody().readAllBytes(), StandardCharsets.UTF_8));
            respond(exchange, """
                    {"accessToken":"dingtalk-access-token","refreshToken":"dingtalk-refresh-token",
                     "expireIn":7200,"corpId":"ding-corp-1"}""");
        });

        this.server.createContext("/v1.0/contact/users/me", exchange -> {
            this.lastDingTalkTokenHeader.set(exchange.getRequestHeaders().getFirst("x-acs-dingtalk-access-token"));
            respond(exchange, """
                    {"nick":"张三","unionId":"union-1","openId":"open-1",
                     "avatarUrl":"https://example.com/a.png","email":"zhangsan@example.com",
                     "stateCode":"86"}""");
        });

        this.server.start();
    }

    @AfterEach
    void stopStubServer() {
        this.server.stop(0);
    }

    @Test
    void tokenExchangePostsJsonWithDingTalkFieldNames() {
        DingTalkTokenResponseClient client = new DingTalkTokenResponseClient(RestClient.create(),
                this.baseUrl + "/v1.0/oauth2/userAccessToken");

        var tokenResponse = client.getTokenResponse(grantRequest());

        assertThat(this.lastMethod.get()).isEqualTo("POST");
        assertThat(this.lastContentType.get()).startsWith("application/json");
        assertThat(this.lastBody.get())
                .contains("\"clientId\":\"ding-app-key\"")
                .contains("\"clientSecret\":\"ding-app-secret\"")
                .contains("\"code\":\"auth-code-1\"")
                .contains("\"grantType\":\"authorization_code\"")
                // OAuth 2.0 的拼写不得泄漏进钉钉的 API
                .doesNotContain("\"client_id\"")
                .doesNotContain("\"grant_type\"");

        assertThat(tokenResponse.getAccessToken().getTokenValue()).isEqualTo("dingtalk-access-token");
        assertThat(tokenResponse.getAccessToken().getTokenType()).isEqualTo(OAuth2AccessToken.TokenType.BEARER);
        assertThat(tokenResponse.getAccessToken().getExpiresAt()).isNotNull();
        assertThat(tokenResponse.getRefreshToken()).isNotNull();
        assertThat(tokenResponse.getRefreshToken().getTokenValue()).isEqualTo("dingtalk-refresh-token");
        assertThat(tokenResponse.getAccessToken().getScopes()).containsExactly("openid");
    }

    @Test
    void userServiceSendsDingTalkHeaderAndMapsUnionId() {
        DingTalkUserService userService = new DingTalkUserService(RestClient.create(),
                this.baseUrl + "/v1.0/contact/users/me", "unionId");

        OAuth2User user = userService.loadUser(userRequest("dingtalk-access-token"));

        assertThat(this.lastDingTalkTokenHeader.get()).isEqualTo("dingtalk-access-token");
        assertThat(user.getName()).isEqualTo("union-1");
        assertThat(user.getAttributes())
                .containsEntry("nick", "张三")
                .containsEntry("openId", "open-1")
                .containsEntry("email", "zhangsan@example.com");
        assertThat(user.getAuthorities()).extracting(Object::toString).containsExactly("ROLE_USER");
    }

    private static OAuth2AuthorizationCodeGrantRequest grantRequest() {
        ClientRegistration registration = ClientRegistration.withRegistrationId("dingtalk")
                .clientId("ding-app-key")
                .clientSecret("ding-app-secret")
                .clientAuthenticationMethod(ClientAuthenticationMethod.CLIENT_SECRET_POST)
                .authorizationGrantType(AuthorizationGrantType.AUTHORIZATION_CODE)
                .redirectUri("http://localhost:8080/login/oauth2/code/dingtalk")
                .scope("openid")
                .authorizationUri("https://login.dingtalk.com/oauth2/auth?prompt=consent")
                .tokenUri("https://api.dingtalk.com/v1.0/oauth2/userAccessToken")
                .userInfoUri("https://api.dingtalk.com/v1.0/contact/users/me")
                .userNameAttributeName("unionId")
                .build();

        OAuth2AuthorizationRequest authorizationRequest = OAuth2AuthorizationRequest.authorizationCode()
                .authorizationUri("https://login.dingtalk.com/oauth2/auth?prompt=consent")
                .clientId("ding-app-key")
                .redirectUri("http://localhost:8080/login/oauth2/code/dingtalk")
                .state("state-1")
                .build();
        OAuth2AuthorizationResponse authorizationResponse = OAuth2AuthorizationResponse
                .success("auth-code-1")
                .redirectUri("http://localhost:8080/login/oauth2/code/dingtalk")
                .state("state-1")
                .build();

        return new OAuth2AuthorizationCodeGrantRequest(registration,
                new OAuth2AuthorizationExchange(authorizationRequest, authorizationResponse));
    }

    private static OAuth2UserRequest userRequest(String accessToken) {
        ClientRegistration registration = ClientRegistration.withRegistrationId("dingtalk")
                .clientId("ding-app-key")
                .clientSecret("ding-app-secret")
                .clientAuthenticationMethod(ClientAuthenticationMethod.CLIENT_SECRET_POST)
                .authorizationGrantType(AuthorizationGrantType.AUTHORIZATION_CODE)
                .redirectUri("http://localhost:8080/login/oauth2/code/dingtalk")
                .scope("openid")
                .authorizationUri("https://login.dingtalk.com/oauth2/auth?prompt=consent")
                .tokenUri("https://api.dingtalk.com/v1.0/oauth2/userAccessToken")
                .userInfoUri("https://api.dingtalk.com/v1.0/contact/users/me")
                .userNameAttributeName("unionId")
                .build();

        OAuth2AccessToken token = new OAuth2AccessToken(OAuth2AccessToken.TokenType.BEARER, accessToken,
                java.time.Instant.now(), java.time.Instant.now().plus(Duration.ofHours(2)));
        return new OAuth2UserRequest(registration, token);
    }

    private static void respond(HttpExchange exchange, String json) throws IOException {
        byte[] body = json.getBytes(StandardCharsets.UTF_8);
        exchange.getResponseHeaders().add("Content-Type", "application/json");
        exchange.sendResponseHeaders(200, body.length);
        exchange.getResponseBody().write(body);
        exchange.close();
    }
}
