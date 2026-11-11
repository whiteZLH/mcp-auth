package com.example.mcpauth.mcp;

import org.springframework.ai.tool.ToolCallbackProvider;
import org.springframework.ai.tool.method.MethodToolCallbackProvider;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

/**
 * 把 {@link McpTools} 发布成 MCP 工具。MCP 服务器的自动配置会拾取每一个
 * {@link ToolCallbackProvider} bean，并把其中的工具注册到 Streamable HTTP 服务器上。
 */
@Configuration(proxyBeanMethods = false)
public class McpToolConfiguration {

    @Bean
    ToolCallbackProvider mcpToolCallbackProvider(McpTools mcpTools) {
        return MethodToolCallbackProvider.builder().toolObjects(mcpTools).build();
    }
}
