package com.example.mcpauth.config;

import java.time.Duration;
import java.util.List;

import org.springframework.boot.context.properties.ConfigurationProperties;

/**
 * 本部署对外公开的身份标识。
 *
 * @param issuer       内嵌授权服务器的签发者标识（{@code iss} 声明、RFC 8414 元数据、
 *                     RFC 9728 的 {@code authorization_servers}）
 * @param resourceUris MCP 端点可接受的 URI。每个访问令牌都会把全部这些 URI 写进 {@code aud}，
 *                     而资源服务器接受受众与其中任意一个匹配的令牌。同时列出 {@code localhost}
 *                     和 {@code 127.0.0.1}（或某个局域网地址），可以消除一整类"为什么我总是收到
 *                     401"的问题，因为客户端对回环地址该用哪种写法并不一致。第一项是主 URI：它
 *                     会作为 {@code resource} 在 RFC 9728 文档中公布。
 * @param scopes       授权服务器和资源元数据都会公布的 scope
 * @param demoUser     本演示中唯一的最终用户，用于登录页
 * @param clients      预先注册好的公开客户端，供无法或不愿使用动态客户端注册的 agent 使用
 * @param refreshTokenMaxLifetime 刷新令牌链的绝对存活时间，从首次签发时开始计算。仅靠轮换会重置
 *                     TTL，所以如果没有这个上限，一直在刷新的客户端就能永久持有一份凭据。
 *                     为零或负数表示不设上限。
 */
@ConfigurationProperties(prefix = "app.security")
public record McpAuthProperties(
        String issuer,
        List<String> resourceUris,
        List<String> scopes,
        DemoUser demoUser,
        List<StaticClient> clients,
        Duration refreshTokenMaxLifetime) {

    /** 演示用最终用户的凭据。 */
    public record DemoUser(String name, String password) {
    }

    /**
     * 在任何客户端连接之前就已经存在的客户端。
     *
     * @param clientId     agent 配置中使用的 {@code client_id}
     * @param clientName   便于人阅读的名称
     * @param redirectUris 允许的 {@code redirect_uri} 值；回环 URI 匹配任意端口
     * @param scopes       该客户端可以请求的 scope；为空表示"支持的全部 scope"
     */
    public record StaticClient(String clientId, String clientName, List<String> redirectUris, List<String> scopes) {
    }

    /** 在受保护资源元数据中作为 {@code resource} 公布的 URI。 */
    public String primaryResourceUri() {
        return this.resourceUris.getFirst();
    }

    /** 某个静态客户端的作用域，默认为本服务器支持的全部作用域。 */
    public List<String> effectiveScopes(StaticClient client) {
        return (client.scopes() == null || client.scopes().isEmpty()) ? this.scopes : client.scopes();
    }
}
