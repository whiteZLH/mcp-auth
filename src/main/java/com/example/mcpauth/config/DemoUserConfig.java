package com.example.mcpauth.config;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.provisioning.InMemoryUserDetailsManager;

/**
 * 允许在 {@code /login} 登录的最终用户。
 *
 * <p>显式声明，而不依赖 {@code spring.security.user.*}，这样凭据就能和其它配置一起出现在
 * {@code application.yml} 里，也能在不动授权服务器配置的前提下替换成真正的
 * {@link UserDetailsService}（LDAP、数据库、SSO）。
 */
@Configuration(proxyBeanMethods = false)
public class DemoUserConfig {

    @Bean
    UserDetailsService userDetailsService(McpAuthProperties properties) {
        UserDetails demoUser = User.withUsername(properties.demoUser().name())
                // {noop}：明文，仅供演示。生产环境请用 BCrypt/Argon2（或外部 IdP）。
                .password("{noop}" + properties.demoUser().password())
                .roles("USER")
                .build();
        return new InMemoryUserDetailsManager(demoUser);
    }
}
