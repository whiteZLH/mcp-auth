package com.example.mcpauth.web;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.util.Arrays;
import java.util.Set;
import java.util.stream.Collectors;

import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import org.springframework.security.oauth2.server.authorization.client.RegisteredClientRepository;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;
import org.springframework.web.util.ContentCachingRequestWrapper;

/**
 * OAuth 2.1 / MCP 端点的诊断日志。
 *
 * <p>没有它，一个在授权流程中途卡住的客户端不会留下任何痕迹：真正值得关注的失败是
 * 安全过滤器链产生并直接返回的 4xx 响应，这些响应根本到不了应用日志。
 *
 * <p>对于 {@code /oauth2/**}、{@code /mcp} 和 {@code /.well-known/**} 上的每个请求，它都会记录
 * 结果；对于授权请求，它还会拿 {@code client_id} 去查线上仓储 —— 这正是
 * “客户端被一次重启弄丢了”与“客户端没问题、是请求错了”之间的区别。
 *
 * <p>记录查询串时，{@code code}、{@code code_verifier}、{@code code_challenge} 以及令牌类参数
 * 的值会被打码。
 */
@Component
public class OAuthDiagnosticsFilter extends OncePerRequestFilter {

    private static final Logger log = LoggerFactory.getLogger(OAuthDiagnosticsFilter.class);

    private static final Set<String> REDACTED = Set.of(
            "code", "code_verifier", "code_challenge", "client_secret",
            "access_token", "refresh_token", "id_token", "password");

    private final RegisteredClientRepository registeredClients;

    public OAuthDiagnosticsFilter(RegisteredClientRepository registeredClients) {
        this.registeredClients = registeredClients;
    }

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain chain)
            throws ServletException, IOException {
        // 注册请求体是唯一值得保留的请求体：它能显示客户端实际请求了什么
        // （client_name、redirect_uris），这是其他任何日志行都看不出来的信息。
        ContentCachingRequestWrapper cached = isRegistration(request)
                ? new ContentCachingRequestWrapper(request, 8192)
                : null;

        long startedAt = System.nanoTime();
        try {
            chain.doFilter(cached != null ? cached : request, response);
        }
        finally {
            String path = request.getRequestURI();
            if (isInteresting(path)) {
                long millis = (System.nanoTime() - startedAt) / 1_000_000;
                log.info("{} {} -> {} ({} ms) {}{}", request.getMethod(), path, response.getStatus(), millis,
                        describe(request), clientHint(request, path));
                if (cached != null) {
                    String body = new String(cached.getContentAsByteArray(), StandardCharsets.UTF_8);
                    if (!body.isBlank()) {
                        log.info("registration payload: {}", body);
                    }
                }
            }
        }
    }

    private static boolean isRegistration(HttpServletRequest request) {
        return "POST".equals(request.getMethod()) && request.getRequestURI().startsWith("/oauth2/register");
    }

    private static boolean isInteresting(String path) {
        return path.startsWith("/oauth2/")
                || path.equals("/mcp")
                || path.startsWith("/.well-known/");
    }

    private static String describe(HttpServletRequest request) {
        String query = request.getQueryString();
        if (query == null || query.isBlank()) {
            return "";
        }
        return "query[" + Arrays.stream(query.split("&"))
                .map(pair -> {
                    int separator = pair.indexOf('=');
                    String name = separator < 0 ? pair : pair.substring(0, separator);
                    return REDACTED.contains(name) ? name + "=***" : pair;
                })
                .collect(Collectors.joining("&")) + "]";
    }

    /** 只用于幂等请求：从已被消费的 POST 请求体里读参数会抛异常。 */
    private String clientHint(HttpServletRequest request, String path) {
        if (!"GET".equals(request.getMethod()) || !path.startsWith("/oauth2/authorize")) {
            return "";
        }
        try {
            String clientId = request.getParameter("client_id");
            if (clientId == null) {
                return " client_id=<missing>";
            }
            boolean known = this.registeredClients.findByClientId(clientId) != null;
            return " client_id=" + clientId + " known=" + known
                    + (known ? "" : "  <-- not in the client registry");
        }
        catch (RuntimeException ex) {
            return " client_id=<unreadable: " + ex.getClass().getSimpleName() + ">";
        }
    }
}
