package com.example.mcpauth.config;

import java.util.LinkedHashSet;
import java.util.List;

import com.nimbusds.jose.jwk.source.JWKSource;
import com.nimbusds.jose.proc.SecurityContext;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.annotation.Order;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.method.configuration.EnableMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.oauth2.core.DelegatingOAuth2TokenValidator;
import org.springframework.security.oauth2.core.OAuth2Error;
import org.springframework.security.oauth2.core.OAuth2ErrorCodes;
import org.springframework.security.oauth2.core.OAuth2TokenValidator;
import org.springframework.security.oauth2.core.OAuth2TokenValidatorResult;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.security.oauth2.jwt.JwtValidators;
import org.springframework.security.oauth2.jwt.NimbusJwtDecoder;
import org.springframework.security.web.SecurityFilterChain;

import org.springaicommunity.mcp.security.server.config.McpServerOAuth2Configurer;

/**
 * 过滤器链 #2：MCP 资源服务器。
 *
 * <p>这里是 OAuth 2.1 与 MCP 授权规范的交汇点：
 *
 * <ul>
 *   <li><b>Bearer JWT 校验</b>，使用同进程内授权服务器的 JWKS。解码器由共享的 {@link JWKSource}
 *       构建，而不是用 {@code issuer-uri}——后者会让应用在启动期间通过 HTTP 调用自己。</li>
 *   <li><b>受众绑定</b>（RFC 8707 语义）：为其他资源签发的令牌不能在这里生效。
 *       {@code app.security.resource-uris} 中的任意一个都会被接受，所以把回环地址写成不同形式
 *       （{@code 127.0.0.1} 与 {@code localhost}）的客户端照样可用。</li>
 *   <li><b>受保护资源元数据</b>（RFC 9728）位于
 *       {@code /.well-known/oauth-protected-resource}，告诉客户端该用哪个授权服务器、该请求哪些
 *       scope。</li>
 *   <li>401 时返回<b>带 {@code resource_metadata} 的 RFC 6750 质询</b>，MCP 客户端正是靠它发现
 *       该去哪里认证。</li>
 * </ul>
 */
@Configuration(proxyBeanMethods = false)
@EnableMethodSecurity
public class McpResourceServerConfig {

    @Bean
    @Order(2)
    SecurityFilterChain mcpServerSecurityFilterChain(HttpSecurity http, JwtDecoder mcpJwtDecoder,
            McpAuthProperties properties) throws Exception {

        // 元数据文档由同一条过滤器链提供，所以它的路径也必须路由到这里。
        http.securityMatcher(
                "/mcp",
                "/mcp/**",
                "/.well-known/oauth-protected-resource",
                "/.well-known/oauth-protected-resource/**");

        http.authorizeHttpRequests(requests -> requests
                // 发现端点必须无需令牌即可访问，否则任何客户端都无法完成引导。
                .requestMatchers("/.well-known/**").permitAll()
                .anyRequest().authenticated());

        // MCP Streamable HTTP 是无状态的 bearer 令牌 API：不使用会话，也不需要 CSRF 令牌。
        http.sessionManagement(session -> session.sessionCreationPolicy(SessionCreationPolicy.STATELESS));
        http.csrf(csrf -> csrf.disable());

        http.with(McpServerOAuth2Configurer.mcpServerOAuth2(), mcp -> mcp
                .authorizationServer(properties.issuer())
                .resourcePath("/mcp")
                .jwtDecoder(mcpJwtDecoder)
                // 把 MCP 会话 id 绑定到已认证的主体上，这样即便会话 id 泄漏，对另一个令牌持有者也
                // 毫无用处（MCP 规范：会话不得共享）。
                .sessionBinding(Customizer.withDefaults())
                // 一旦发布自定义 customizer 就会替换掉默认实现，所以授权服务器、资源名称和作用域
                // 都在这里逐一写明（RFC 9728 §2）。
                .protectedResourceMetadataCustomizer(metadata -> metadata
                        .resource(properties.primaryResourceUri())
                        .authorizationServer(properties.issuer())
                        .resourceName("mcp-auth MCP server")
                        .scopes(scopes -> scopes.addAll(properties.scopes()))));

        return http.build();
    }

    /**
     * JWT 解码器：先校验签名和标准声明，再做受众检查。
     *
     * <p>受众检查放在这里，而不是用社区 configurer 的 {@code validateAudienceClaim(true)}——后者是
     * 拿从传入请求推导出的 URI 来比较。显式配置一组 URI 在对"接受什么"上更严格（只接受本部署
     * 声明过的 URI），在对"客户端怎么访问"上却更宽松。
     */
    @Bean
    JwtDecoder mcpJwtDecoder(JWKSource<SecurityContext> jwkSource, McpAuthProperties properties) {
        NimbusJwtDecoder decoder = NimbusJwtDecoder.withJwkSource(jwkSource).build();
        decoder.setJwtValidator(new DelegatingOAuth2TokenValidator<>(
                JwtValidators.createDefaultWithIssuer(properties.issuer()),
                new AudienceValidator(properties.resourceUris())));
        return decoder;
    }

    /** 只要令牌的某个受众是本部署提供服务的 URI，就接受该令牌。 */
    static final class AudienceValidator implements OAuth2TokenValidator<Jwt> {

        private final List<String> allowedAudiences;

        AudienceValidator(List<String> allowedAudiences) {
            this.allowedAudiences = List.copyOf(new LinkedHashSet<>(allowedAudiences));
        }

        @Override
        public OAuth2TokenValidatorResult validate(Jwt token) {
            boolean matches = token.getAudience().stream().anyMatch(this.allowedAudiences::contains);
            if (matches) {
                return OAuth2TokenValidatorResult.success();
            }
            return OAuth2TokenValidatorResult.failure(new OAuth2Error(OAuth2ErrorCodes.INVALID_TOKEN,
                    "The token audience does not match this MCP server (expected one of "
                            + this.allowedAudiences + ", got " + token.getAudience() + ")",
                    null));
        }
    }
}
