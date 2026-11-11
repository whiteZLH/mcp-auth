package com.example.mcpauth;

import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.time.Instant;
import java.util.List;
import java.util.Map;
import java.util.stream.Collectors;

import com.nimbusds.jose.jwk.source.JWKSource;
import com.nimbusds.jose.proc.SecurityContext;
import org.junit.jupiter.api.Test;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.security.oauth2.jose.jws.SignatureAlgorithm;
import org.springframework.security.oauth2.jwt.JwtClaimsSet;
import org.springframework.security.oauth2.jwt.JwsHeader;
import org.springframework.security.oauth2.jwt.JwtEncoder;
import org.springframework.security.oauth2.jwt.JwtEncoderParameters;
import org.springframework.security.oauth2.jwt.NimbusJwtEncoder;

import com.example.mcpauth.config.McpAuthProperties;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * 针对真实 HTTP 端口的黑盒测试。
 *
 * <p>它们恰好覆盖那些容易写错、又无法仅凭配置看出的部分：发现文档、引导客户端接入的 401 质询、
 * 受众（aud）校验、动态客户端注册，以及工具调用基于作用域的授权。
 */
@SpringBootTest(webEnvironment = SpringBootTest.WebEnvironment.RANDOM_PORT)
class McpAuthIntegrationTests {

    private static final String INITIALIZE_BODY = """
            {"jsonrpc":"2.0","id":1,"method":"initialize","params":{
              "protocolVersion":"2025-06-18","capabilities":{},
              "clientInfo":{"name":"integration-test","version":"1.0.0"}}}""";

    private final HttpClient http = HttpClient.newHttpClient();

    @Value("${local.server.port}")
    private int port;

    @Autowired
    private JWKSource<SecurityContext> jwkSource;

    @Autowired
    private McpAuthProperties properties;

    private String baseUrl() {
        return "http://localhost:" + this.port;
    }

    /** 配置中的主 MCP 资源 URI，与测试随机端口无关。 */
    private String resourceUri() {
        return this.properties.primaryResourceUri();
    }

    @Test
    void protectedResourceMetadataIsDiscoverableWithoutAuthentication() throws Exception {
        Response response = get("/.well-known/oauth-protected-resource/mcp");

        assertThat(response.status()).isEqualTo(200);
        assertThat(response.body()).contains("\"resource\":\"" + resourceUri() + "\"");
        assertThat(response.body()).contains("\"authorization_servers\":[\"" + this.properties.issuer() + "\"]");
        assertThat(response.body()).contains("mcp.tools.call");
    }

    @Test
    void authorizationServerMetadataAdvertisesPkceAndRegistration() throws Exception {
        Response response = get("/.well-known/oauth-authorization-server");

        assertThat(response.status()).isEqualTo(200);
        assertThat(response.body()).contains("\"code_challenge_methods_supported\":[\"S256\"]");
        assertThat(response.body()).contains("/oauth2/register");
    }

    /**
     * 浏览器路径的回归测试：未认证的授权请求必须把用户导向登录页。
     *
     * <p>当该端点被放开为 {@code permitAll()} 时，Spring Security 的授权端点对匿名主体返回
     * {@code invalid_request: OAuth 2.0 Parameter: principal}，并直接重定向到客户端的回调地址。
     * 登录页从未出现，于是交互式客户端（WorkBuddy、Cursor、Inspector……）会一直等待一个
     * 永远不会到来的授权码。
     */
    @Test
    void unauthenticatedAuthorizeRequestRedirectsToLoginPage() throws Exception {
        String authorizeUrl = "/oauth2/authorize?response_type=code&client_id=mcp-cli"
                + "&redirect_uri=http%3A%2F%2F127.0.0.1%3A8080%2Fcallback"
                + "&scope=mcp.tools.read&state=regression"
                + "&code_challenge=abcdefghijklmnopqrstuvwxyz0123456789ABCDEFGHIJ&code_challenge_method=S256";

        Response response = getWithoutFollowingRedirects(authorizeUrl);

        assertThat(response.status()).isEqualTo(302);
        assertThat(response.header("Location")).endsWith("/login");
    }

    @Test
    void unauthenticatedMcpCallIsChallengedWithResourceMetadata() throws Exception {
        Response response = post("/mcp", INITIALIZE_BODY, Map.of());

        assertThat(response.status()).isEqualTo(401);
        assertThat(response.header("WWW-Authenticate"))
                .contains("Bearer")
                .contains("resource_metadata=" + baseUrl() + "/.well-known/oauth-protected-resource/mcp");
    }

    @Test
    void tokenForThisResourceIsAccepted() throws Exception {
        Response response = post("/mcp", INITIALIZE_BODY,
                Map.of("Authorization", "Bearer " + token(resourceUri(), "mcp.tools.read mcp.tools.call")));

        assertThat(response.status()).isEqualTo(200);
        assertThat(response.body()).contains("mcp-auth-server");
    }

    @Test
    void tokenMintedForAnotherResourceIsRejected() throws Exception {
        // 签名正确、颁发者正确、未过期——只有受众（aud）是错的。
        String token = token("http://localhost:9999/some-other-mcp", "mcp.tools.read mcp.tools.call");

        Response response = post("/mcp", INITIALIZE_BODY, Map.of("Authorization", "Bearer " + token));

        assertThat(response.status()).isEqualTo(401);
    }

    @Test
    void tokenForTheOtherLoopbackSpellingIsAccepted() throws Exception {
        // 127.0.0.1 与 localhost 指向同一台服务器，但字符串不同；两者都已配置。
        String token = token("http://127.0.0.1:8080/mcp", "mcp.tools.read mcp.tools.call");

        Response response = post("/mcp", INITIALIZE_BODY, Map.of("Authorization", "Bearer " + token));

        assertThat(response.status()).isEqualTo(200);
    }

    @Test
    void toolCallNeedsTheToolCallScope() throws Exception {
        String readOnlyToken = token(resourceUri(), "mcp.tools.read");
        Response initialize = post("/mcp", INITIALIZE_BODY, Map.of("Authorization", "Bearer " + readOnlyToken));
        assertThat(initialize.status()).isEqualTo(200);

        String sessionId = initialize.header("Mcp-Session-Id");
        Map<String, String> headers = Map.of("Authorization", "Bearer " + readOnlyToken);
        if (sessionId != null && !sessionId.isBlank()) {
            headers = Map.of("Authorization", "Bearer " + readOnlyToken, "Mcp-Session-Id", sessionId);
        }

        Response allowed = post("/mcp",
                """
                {"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"now","arguments":{}}}""",
                headers);
        assertThat(allowed.body()).contains("2026").doesNotContain("\"isError\":true");

        Response denied = post("/mcp",
                """
                {"jsonrpc":"2.0","id":3,"method":"tools/call","params":{"name":"add","arguments":{"a":2,"b":3}}}""",
                headers);
        assertThat(denied.body()).containsIgnoringCase("Access Denied");
    }

    @Test
    void dynamicClientRegistrationAcceptsLoopbackRedirectAndScopes() throws Exception {
        String registration = """
                {"client_name":"integration-test-client",
                 "redirect_uris":["http://127.0.0.1:43512/callback"],
                 "grant_types":["authorization_code","refresh_token"],
                 "response_types":["code"],
                 "token_endpoint_auth_method":"none",
                 "scope":"mcp.tools.read"}""";

        Response response = postJson("/oauth2/register", registration);

        assertThat(response.status()).isEqualTo(201);
        assertThat(response.body()).contains("client_id");
        assertThat(response.body()).contains("mcp.tools.read");
    }

    // ------------------------------------------------------------------ 辅助方法

    private String token(String audience, String scopes) {
        JwtEncoder encoder = new NimbusJwtEncoder(this.jwkSource);
        Instant now = Instant.now();
        JwtClaimsSet claims = JwtClaimsSet.builder()
                .issuer(this.properties.issuer())
                .subject("user")
                .audience(List.of(audience))
                .issuedAt(now)
                .expiresAt(now.plusSeconds(300))
                .claim("scope", scopes)
                .build();
        JwsHeader header = JwsHeader.with(SignatureAlgorithm.RS256).build();
        return encoder.encode(JwtEncoderParameters.from(header, claims)).getTokenValue();
    }

    private Response get(String path) throws Exception {
        HttpResponse<String> response = this.http.send(
                HttpRequest.newBuilder(URI.create(baseUrl() + path)).GET().build(),
                HttpResponse.BodyHandlers.ofString());
        return new Response(response.statusCode(), response.headers().map(), response.body());
    }

    /** 保留 302 本身：断言的目标正是 Location 响应头。 */
    private Response getWithoutFollowingRedirects(String path) throws Exception {
        HttpClient noRedirect = HttpClient.newBuilder()
                .followRedirects(HttpClient.Redirect.NEVER)
                .build();
        HttpResponse<String> response = noRedirect.send(
                HttpRequest.newBuilder(URI.create(baseUrl() + path)).GET().build(),
                HttpResponse.BodyHandlers.ofString());
        return new Response(response.statusCode(), response.headers().map(), response.body());
    }

    private Response post(String path, String body, Map<String, String> headers) throws Exception {
        HttpRequest.Builder builder = HttpRequest.newBuilder(URI.create(baseUrl() + path))
                .header("Content-Type", "application/json")
                .header("Accept", "application/json, text/event-stream")
                .POST(HttpRequest.BodyPublishers.ofString(body));
        headers.forEach(builder::header);
        HttpResponse<String> response = this.http.send(builder.build(), HttpResponse.BodyHandlers.ofString());
        return new Response(response.statusCode(), response.headers().map(), unwrapSse(response));
    }

    private Response postJson(String path, String body) throws Exception {
        return post(path, body, Map.of());
    }

    /** Streamable HTTP 传输可能以 SSE 流作答；这里把它折叠回 JSON。 */
    private static String unwrapSse(HttpResponse<String> response) {
        String contentType = response.headers().firstValue("Content-Type").orElse("");
        if (!contentType.contains("text/event-stream")) {
            return response.body();
        }
        return response.body().lines()
                .filter(line -> line.startsWith("data:"))
                .map(line -> line.substring(5).strip())
                .collect(Collectors.joining());
    }

    record Response(int status, Map<String, List<String>> headers, String body) {

        String header(String name) {
            return this.headers.entrySet().stream()
                    .filter(entry -> entry.getKey().equalsIgnoreCase(name))
                    .map(entry -> String.join(",", entry.getValue()))
                    .findFirst()
                    .orElse("");
        }
    }
}
