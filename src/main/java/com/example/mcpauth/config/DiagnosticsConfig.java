package com.example.mcpauth.config;

import org.springframework.boot.web.servlet.FilterRegistrationBean;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

import com.example.mcpauth.web.OAuthDiagnosticsFilter;

/**
 * 把诊断过滤器放到安全过滤器链之前。
 *
 * <p>顺序很关键：Spring Security 的链位于 {@code -100}，被拒绝的请求由它自己直接应答，不会再往
 * 下传递。因此用默认顺序注册的过滤器永远看不到那些值得记录的 401/400 响应。
 */
@Configuration(proxyBeanMethods = false)
public class DiagnosticsConfig {

    private static final int IN_FRONT_OF_SECURITY = -101;

    @Bean
    FilterRegistrationBean<OAuthDiagnosticsFilter> oauthDiagnosticsFilter(OAuthDiagnosticsFilter filter) {
        FilterRegistrationBean<OAuthDiagnosticsFilter> registration = new FilterRegistrationBean<>(filter);
        registration.setOrder(IN_FRONT_OF_SECURITY);
        registration.addUrlPatterns("/*");
        return registration;
    }
}
