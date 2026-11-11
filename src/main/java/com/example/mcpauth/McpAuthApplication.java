package com.example.mcpauth;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.boot.context.properties.ConfigurationPropertiesScan;

/**
 * 单进程演示程序，同时扮演两个角色：
 *
 * <ul>
 *   <li><b>OAuth 2.1 授权服务器</b>（Spring Authorization Server，内嵌）：
 *       强制 PKCE 的公开客户端、动态客户端注册（RFC 7591）、
 *       授权服务器元数据（RFC 8414）。</li>
 *   <li><b>MCP 资源服务器</b>（Spring AI MCP server，在 {@code /mcp} 上提供 Streamable HTTP）：
 *       校验 bearer JWT、发布受保护资源元数据（RFC 9728），并把令牌绑定到自身的受众
 *       （RFC 8707 语义）。</li>
 * </ul>
 */
@SpringBootApplication
@ConfigurationPropertiesScan
public class McpAuthApplication {

    public static void main(String[] args) {
        SpringApplication.run(McpAuthApplication.class, args);
    }
}
