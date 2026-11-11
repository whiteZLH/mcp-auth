package com.example.mcpauth.login;

import org.springframework.boot.autoconfigure.condition.ConditionalOnExpression;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.oauth2.client.registration.ClientRegistration;
import org.springframework.security.oauth2.client.registration.ClientRegistrationRepository;
import org.springframework.security.oauth2.client.registration.InMemoryClientRegistrationRepository;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.core.ClientAuthenticationMethod;
import org.springframework.web.client.RestClient;

/**
 * 把钉钉接入为授权服务器的用户身份提供方。
 *
 * <p>这里只替换<em>由谁来认证用户</em>。MCP 一侧完全不变：令牌仍由本应用签名，受保护资源元数据、
 * 动态客户端注册、受众绑定和作用域都照常工作，MCP 客户端也从不会得知钉钉的存在。
 *
 * <p>除非设置了 {@code app.login.dingtalk.client-id}，否则该配置不生效，因此项目仍可用本地演示账号
 * 运行，且无需访问钉钉的网络。
 */
@Configuration(proxyBeanMethods = false)
@EnableConfigurationProperties(DingTalkLoginProperties.class)
// 空的 client-id（application.yml 中的默认值）必须把整套功能关掉，而 @ConditionalOnProperty
// 做不到这一点：空值也会被视为"已存在"。
@ConditionalOnExpression("'${app.login.dingtalk.client-id:}'.trim().length() > 0")
public class DingTalkLoginConfiguration {

    static final String REGISTRATION_ID = "dingtalk";

    /**
     * 钉钉的客户端注册。
     *
     * <p>这里体现钉钉的两处特殊之处：
     *
     * <ul>
     *   <li>{@code prompt=consent} 是必需的，而 Spring 没有对应设置，所以直接写进授权 URI —
     *       Spring 追加标准查询参数时会保留已有的参数；</li>
     *   <li>用户名属性是 {@code unionId}。{@code openId} 只作用于单个应用，因此跨应用的稳定身份
     *       必须使用 {@code unionId}。</li>
     * </ul>
     */
    @Bean
    ClientRegistrationRepository dingTalkClientRegistrations(DingTalkLoginProperties properties) {
        ClientRegistration registration = ClientRegistration.withRegistrationId(REGISTRATION_ID)
                .clientName("钉钉")
                .clientId(properties.clientId())
                .clientSecret(properties.clientSecret())
                // 自定义的令牌客户端在请求体里发送凭据；这里只需取一个不会让默认客户端
                // 尝试使用 Basic 认证的值。
                .clientAuthenticationMethod(ClientAuthenticationMethod.CLIENT_SECRET_POST)
                .authorizationGrantType(AuthorizationGrantType.AUTHORIZATION_CODE)
                .redirectUri("{baseUrl}/login/oauth2/code/{registrationId}")
                .scope("openid")
                .authorizationUri(properties.authorizeUri())
                .tokenUri(properties.tokenUri())
                .userInfoUri(properties.userInfoUri())
                .userNameAttributeName(properties.userNameAttribute())
                .build();
        return new InMemoryClientRegistrationRepository(registration);
    }

    @Bean
    DingTalkTokenResponseClient dingTalkTokenResponseClient(DingTalkLoginProperties properties) {
        return new DingTalkTokenResponseClient(RestClient.create(), properties.tokenUri());
    }

    @Bean
    DingTalkUserService dingTalkUserService(DingTalkLoginProperties properties) {
        return new DingTalkUserService(RestClient.create(), properties.userInfoUri(),
                properties.userNameAttribute());
    }
}
