package com.example.mcpauth.mcp;

import java.time.OffsetDateTime;
import java.time.format.DateTimeFormatter;
import java.util.Map;

import org.springframework.ai.tool.annotation.Tool;
import org.springframework.ai.tool.annotation.ToolParam;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.stereotype.Service;

/**
 * MCP 对外暴露的工具面。
 *
 * <p>这里能看出两层保护：
 *
 * <ul>
 *   <li>认证 —— 整个 {@code /mcp} 端点都需要有效的 bearer 令牌，由安全过滤器链强制执行；</li>
 *   <li>授权 —— 每个工具都声明自己需要的作用域。{@code @PreAuthorize} 通过方法级安全生效，
 *       Spring Security 把令牌的 {@code scope} 声明映射成 {@code SCOPE_*} 权限，所以一个
 *       有效但只被授予 {@code mcp.tools.read} 的令牌无法调用 {@code add}。</li>
 * </ul>
 */
@Service
public class McpTools {

    @Tool(name = "echo", description = "Echo the given text back. Useful to verify the OAuth 2.1 protected call path end to end.")
    @PreAuthorize("hasAuthority('SCOPE_mcp.tools.read')")
    public String echo(@ToolParam(description = "Text to echo back") String text) {
        return "echo: " + text;
    }

    @Tool(name = "now", description = "Return the current server date-time in ISO-8601 format.")
    @PreAuthorize("hasAuthority('SCOPE_mcp.tools.read')")
    public String now() {
        return OffsetDateTime.now().format(DateTimeFormatter.ISO_OFFSET_DATE_TIME);
    }

    @Tool(name = "add", description = "Add two integers and return the sum. Requires the mcp.tools.call scope.")
    @PreAuthorize("hasAuthority('SCOPE_mcp.tools.call')")
    public int add(
            @ToolParam(description = "First addend") int a,
            @ToolParam(description = "Second addend") int b) {
        return a + b;
    }

    @Tool(name = "whoami", description = "Describe the authenticated caller of this MCP request: subject and scopes.")
    @PreAuthorize("hasAuthority('SCOPE_mcp.tools.read')")
    public Map<String, Object> whoami() {
        Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
        if (authentication == null || !authentication.isAuthenticated()) {
            return Map.of("authenticated", false);
        }
        return Map.of(
                "authenticated", true,
                "subject", String.valueOf(authentication.getName()),
                "authorities", authentication.getAuthorities().stream().map(Object::toString).toList());
    }
}
