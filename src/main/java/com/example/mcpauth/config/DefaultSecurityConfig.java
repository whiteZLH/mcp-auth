package com.example.mcpauth.config;

import org.springframework.beans.factory.ObjectProvider;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.annotation.Order;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.web.SecurityFilterChain;

import com.example.mcpauth.login.DingTalkTokenResponseClient;
import com.example.mcpauth.login.DingTalkUserService;

/**
 * 过滤器链 #3：其余所有请求——落地页，以及授权服务器重定向过去的登录页。
 *
 * <p>有意与 MCP 那条链分开：登录流程基于会话，而 MCP 端点是无状态的。
 *
 * <p>钉钉登录是叠加在演示账号之上的，而不是替换它：{@code /login} 上两个入口都可见，且本地账号
 * 在没有任何钉钉凭据时依然可用，这正是本项目能够离线运行的原因。
 */
@Configuration(proxyBeanMethods = false)
public class DefaultSecurityConfig {

    @Bean
    @Order(3)
    SecurityFilterChain defaultSecurityFilterChain(HttpSecurity http,
            ObjectProvider<DingTalkUserService> dingTalkUserService,
            ObjectProvider<DingTalkTokenResponseClient> dingTalkTokenClient) throws Exception {

        // 这里保持启用 CSRF：表单登录的 POST 请求正是它要保护的对象。
        http.authorizeHttpRequests(requests -> requests.anyRequest().permitAll());
        http.formLogin(formLogin -> formLogin.loginPage("/login"));
        http.logout(Customizer.withDefaults());

        DingTalkUserService userService = dingTalkUserService.getIfAvailable();
        DingTalkTokenResponseClient tokenClient = dingTalkTokenClient.getIfAvailable();
        if (userService != null && tokenClient != null) {
            http.oauth2Login(oauth2Login -> oauth2Login
                    .loginPage("/login")
                    // 钉钉在这两个步骤上都偏离了 OAuth 2.0 的默认行为，所以令牌交换和用户资料
                    // 查询都被替换掉。
                    .tokenEndpoint(token -> token.accessTokenResponseClient(tokenClient))
                    .userInfoEndpoint(userInfo -> userInfo.userService(userService)));
        }
        return http.build();
    }
}
