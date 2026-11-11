package com.example.mcpauth.config;

import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.time.Instant;
import java.util.Base64;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Set;
import java.util.UUID;
import java.util.function.Consumer;
import java.util.stream.Collectors;

import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.jwk.RSAKey;
import com.nimbusds.jose.jwk.source.JWKSource;
import com.nimbusds.jose.proc.SecurityContext;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.annotation.Order;
import org.springframework.core.convert.converter.Converter;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.crypto.keygen.Base64StringKeyGenerator;
import org.springframework.security.crypto.keygen.StringKeyGenerator;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.core.ClientAuthenticationMethod;
import org.springframework.security.oauth2.core.OAuth2RefreshToken;
import org.springframework.security.oauth2.core.OAuth2Token;
import org.springframework.security.oauth2.jwt.NimbusJwtEncoder;
import org.springframework.security.oauth2.server.authorization.OAuth2AuthorizationService;
import org.springframework.security.oauth2.server.authorization.OAuth2ClientRegistration;
import org.springframework.security.oauth2.server.authorization.authentication.OAuth2ClientRegistrationAuthenticationContext;
import org.springframework.security.oauth2.server.authorization.authentication.OAuth2ClientRegistrationAuthenticationProvider;
import org.springframework.security.oauth2.server.authorization.authentication.OAuth2ClientRegistrationAuthenticationValidator;
import org.springframework.security.oauth2.server.authorization.InMemoryOAuth2AuthorizationService;
import org.springframework.security.oauth2.server.authorization.authentication.OAuth2RefreshTokenAuthenticationProvider;
import org.springframework.security.oauth2.server.authorization.client.InMemoryRegisteredClientRepository;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClientRepository;
import org.springframework.security.oauth2.server.authorization.converter.OAuth2ClientRegistrationRegisteredClientConverter;
import org.springframework.security.oauth2.server.authorization.settings.AuthorizationServerSettings;
import org.springframework.security.oauth2.server.authorization.settings.ClientSettings;
import org.springframework.security.oauth2.server.authorization.settings.TokenSettings;
import org.springframework.security.oauth2.server.authorization.token.DelegatingOAuth2TokenGenerator;
import org.springframework.security.oauth2.server.authorization.token.JwtEncodingContext;
import org.springframework.security.oauth2.server.authorization.token.JwtGenerator;
import org.springframework.security.oauth2.server.authorization.token.OAuth2AccessTokenGenerator;
import org.springframework.security.oauth2.server.authorization.token.OAuth2RefreshTokenGenerator;
import org.springframework.security.oauth2.server.authorization.token.OAuth2TokenCustomizer;
import org.springframework.security.oauth2.server.authorization.token.OAuth2TokenGenerator;
import org.springframework.security.oauth2.server.authorization.OAuth2TokenType;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.LoginUrlAuthenticationEntryPoint;
import org.springframework.security.web.servlet.util.matcher.PathPatternRequestMatcher;
import org.springframework.security.web.util.matcher.AndRequestMatcher;
import org.springframework.security.web.util.matcher.NegatedRequestMatcher;
import org.springframework.security.web.util.matcher.OrRequestMatcher;

import com.example.mcpauth.oauth.AbsoluteLifetimeRefreshTokenAuthenticationProvider;
import com.example.mcpauth.oauth.FirstIssuanceTrackingAuthorizationService;
import com.example.mcpauth.oauth.PublicClientRefreshTokenAuthenticationConverter;
import com.example.mcpauth.oauth.PublicClientRefreshTokenAuthenticationProvider;

/**
 * 链 #1：内嵌的 OAuth 2.1 授权服务器。
 *
 * <p>MCP 授权规范在普通 OAuth 2.0 之上额外要求的内容，以及它们在本类中的落点：
 *
 * <table border="1">
 *   <tr><th>要求</th><th>实现</th></tr>
 *   <tr><td>只支持授权码 + PKCE S256，且允许公开客户端</td>
 *       <td>{@code ClientAuthenticationMethod.NONE} + {@code requireProofKey(true)}</td></tr>
 *   <tr><td>RFC 8414 授权服务器元数据，含注册端点</td>
 *       <td>Spring Security 的 {@code oauth2AuthorizationServer(...)}</td></tr>
 *   <tr><td>RFC 7591 动态客户端注册，无需用户介入</td>
 *       <td>{@code clientRegistrationEndpoint(...).openRegistrationAllowed(true)}</td></tr>
 *   <tr><td>任意端口上的回环重定向 URI（RFC 8252 §7.3）</td>
 *       <td>由默认的重定向 URI 校验器覆盖</td></tr>
 *   <tr><td>绑定到 {@code aud} 声明中的 RFC 8707 资源指示符</td>
 *       <td>{@link #mcpTokenGenerator} + {@link #mcpTokenCustomizer}</td></tr>
 * </table>
 */
@Configuration(proxyBeanMethods = false)
public class AuthorizationServerConfig {

    private static final Logger log = LoggerFactory.getLogger(AuthorizationServerConfig.class);

    @Bean
    @Order(1)
    SecurityFilterChain authorizationServerSecurityFilterChain(HttpSecurity http,
            Consumer<OAuth2ClientRegistrationAuthenticationContext> dynamicClientRegistrationValidator,
            Converter<OAuth2ClientRegistration, RegisteredClient> mcpRegisteredClientConverter,
            RegisteredClientRepository registeredClients,
            OAuth2AuthorizationService authorizationService,
            McpAuthProperties properties) throws Exception {

        // 故意在这里内联构建：把 AuthenticationProvider 发布为 @Bean 会让 Spring Boot
        // 用它配置*全局* AuthenticationManager，并丢掉 UserDetailsService，
        // 从而静默破坏表单登录（登录页报 "Bad credentials"）。
        PublicClientRefreshTokenAuthenticationConverter publicClientRefreshTokenConverter =
                new PublicClientRefreshTokenAuthenticationConverter(registeredClients);
        PublicClientRefreshTokenAuthenticationProvider publicClientRefreshTokenProvider =
                new PublicClientRefreshTokenAuthenticationProvider();

        http.oauth2AuthorizationServer(authorizationServer -> authorizationServer
                // 包装内存存储，使首次刷新令牌的签发时间在轮换后仍能保留。
                .authorizationService(authorizationService)
                // 公开客户端用刷新令牌兑换时没有 code_verifier 可以证明自己，
                // 因此令牌端点需要学会如何认证这一种特定形态的请求。
                .clientAuthentication(clientAuthentication -> clientAuthentication
                        .authenticationConverters(converters -> converters.add(0, publicClientRefreshTokenConverter))
                        .authenticationProviders(providers -> providers.add(0, publicClientRefreshTokenProvider)))
                .tokenEndpoint(tokenEndpoint -> tokenEndpoint
                        .authenticationProviders(providers -> providers.replaceAll(provider ->
                                provider instanceof OAuth2RefreshTokenAuthenticationProvider refreshProvider
                                        ? new AbsoluteLifetimeRefreshTokenAuthenticationProvider(
                                                refreshProvider, authorizationService,
                                                properties.refreshTokenMaxLifetime())
                                        : provider)))
                .clientRegistrationEndpoint(registration -> registration
                        .openRegistrationAllowed(true)
                        // 替换该 provider 的校验器/转换器，让 MCP 客户端能够
                        // 注册它们从受保护资源元数据中读到的作用域。
                        .authenticationProviders(providers -> providers.replaceAll(provider -> {
                            if (provider instanceof OAuth2ClientRegistrationAuthenticationProvider selfRegistered) {
                                selfRegistered.setAuthenticationValidator(dynamicClientRegistrationValidator);
                                selfRegistered.setRegisteredClientConverter(mcpRegisteredClientConverter);
                            }
                            return provider;
                        }))));

        // 授权服务器提供的一切端点，*除了*客户端登录重定向端点：
        // /oauth2/authorization/{registrationId} 属于默认链上的 oauth2Login。让本链占用它
        // 会使该 URL 返回 404，并彻底破坏委托登录。
        http.securityMatcher(new AndRequestMatcher(
                new NegatedRequestMatcher(PathPatternRequestMatcher.withDefaults()
                        .matcher("/oauth2/authorization/**")),
                new OrRequestMatcher(
                        PathPatternRequestMatcher.withDefaults().matcher("/oauth2/**"),
                        PathPatternRequestMatcher.withDefaults().matcher("/.well-known/oauth-authorization-server/**"),
                        PathPatternRequestMatcher.withDefaults().matcher("/.well-known/openid-configuration/**"),
                        PathPatternRequestMatcher.withDefaults().matcher("/connect/**"),
                        PathPatternRequestMatcher.withDefaults().matcher("/userinfo"))));

        // 各端点自行执行自己的规则（客户端认证、PKCE、用户登录）。
        // 匿名访问正是开放动态客户端注册得以实现的原因……
        http.authorizeHttpRequests(requests -> requests
                // ……但授权端点是唯一一处必须把*未认证*调用转成登录重定向的地方。若交给端点自己处理，
                // 匿名主体会得到 "invalid_request: OAuth 2.0 Parameter: principal"
                // 并被重定向到客户端的回调地址——浏览器永远看不到登录页，客户端则无限等待授权码。
                // 在这里要求认证，Spring Security 就会把浏览器送到登录表单，然后再回到这个完全相同的请求。
                .requestMatchers("/oauth2/authorize").authenticated()
                .anyRequest().permitAll());

        // 这些端点是机器对机器的 POST，这里没有需要保护的浏览器表单。
        http.csrf(csrf -> csrf.disable());

        // 本链保护的所有内容都面向浏览器，因此未认证请求会进入登录页，并经由保存的请求返回。
        http.exceptionHandling(exceptionHandling -> exceptionHandling
                .authenticationEntryPoint(new LoginUrlAuthenticationEntryPoint("/login")));

        return http.build();
    }

    /**
     * 在任何人连接之前就已存在的客户端，通过 {@code app.security.clients} 声明。
     *
     * <p>支持动态客户端注册的 Agent 不需要在这里添加条目。这个列表是为那些坚持要用固定
     * {@code client_id} 配置的客户端准备的（VS Code 的 {@code "oauth": {"clientId": ...}} 块是常见例子）。
     * 注册端点会把新客户端写入同一个内存仓储。
     */
    @Bean
    RegisteredClientRepository registeredClientRepository(McpAuthProperties properties) {
        List<RegisteredClient> clients = properties.clients().stream()
                .map(client -> staticClient(properties, client))
                .toList();

        // 动态客户端注册端点正是通过 save() 写入。
        return new InMemoryRegisteredClientRepository(clients);
    }

    private static RegisteredClient staticClient(McpAuthProperties properties, McpAuthProperties.StaticClient client) {
        RegisteredClient.Builder builder = RegisteredClient.withId(UUID.randomUUID().toString())
                .clientId(client.clientId())
                .clientName(client.clientName() == null ? client.clientId() : client.clientName())
                .clientAuthenticationMethod(ClientAuthenticationMethod.NONE)
                .authorizationGrantType(AuthorizationGrantType.AUTHORIZATION_CODE)
                .authorizationGrantType(AuthorizationGrantType.REFRESH_TOKEN)
                .tokenSettings(refreshTokenRotation())
                .clientSettings(ClientSettings.builder()
                        .requireProofKey(true)
                        .requireAuthorizationConsent(false)
                        .build());
        client.redirectUris().forEach(builder::redirectUri);
        properties.effectiveScopes(client).forEach(builder::scope);
        return builder.build();
    }

    /**
     * 轮换刷新令牌：每次刷新都返回一个新的，并使旧值失效。
     *
     * <p>这一点在这里比通常更重要，因为公开客户端的刷新令牌是纯粹的持有者凭证——
     * 没有任何东西能区分真正的客户端和偷到令牌的人。轮换至少能让被盗令牌只能单次使用
     * 且可被发现：旧值的第二次使用会得到 {@code invalid_grant}。
     *
     * <p>请注意（文档说明 {@code reuseRefreshTokens} 为 {@code false} 时“会签发新的刷新令牌”），
     * 每次轮换都会重新开始 TTL，因此一直刷新的客户端就会永远持有一个有效凭证——
     * 见 spring-authorization-server issue #2318。
     */
    private static TokenSettings refreshTokenRotation() {
        return TokenSettings.builder()
                .reuseRefreshTokens(false)
                .build();
    }

    @Bean
    AuthorizationServerSettings authorizationServerSettings(McpAuthProperties properties) {
        return AuthorizationServerSettings.builder().issuer(properties.issuer()).build();
    }

    /**
     * 授权存储，做了包装，使首次刷新令牌的签发时间能跨轮换被记住
     * （见 {@link FirstIssuanceTrackingAuthorizationService}）。
     *
     * <p>内存实现：每次重启都会使所有授权失效，这对本演示是预期行为，
     * 但在真实部署中这是第一个要换成 JDBC 存储的东西。
     */
    @Bean
    OAuth2AuthorizationService authorizationService() {
        return new FirstIssuanceTrackingAuthorizationService(new InMemoryOAuth2AuthorizationService());
    }

    /**
     * 用于签发访问令牌以及 JWKS 端点的签名密钥。
     *
     * <p>每次启动都重新生成：做演示没问题，生产环境则毫无用处（令牌随进程消亡，
     * 另一个实例也无法验证第一个实例签发的令牌）。
     */
    @Bean
    JWKSource<SecurityContext> jwkSource() throws Exception {
        KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("RSA");
        keyPairGenerator.initialize(2048);
        KeyPair keyPair = keyPairGenerator.generateKeyPair();
        RSAKey rsaKey = new RSAKey.Builder((RSAPublicKey) keyPair.getPublic())
                .privateKey((RSAPrivateKey) keyPair.getPrivate())
                .keyID(UUID.randomUUID().toString())
                .build();
        JWKSet jwkSet = new JWKSet(rsaKey);
        return (jwkSelector, securityContext) -> jwkSelector.select(jwkSet);
    }

    /**
     * 令牌生成器：访问令牌用 JWT（这样资源服务器可以对照 JWKS 离线验证它们），
     * 刷新令牌用随机字符串。
     *
     * <p>这行调试日志是特意留的：是否签发刷新令牌取决于客户端注册的授权类型，
     * 而“刷新令牌悄悄缺失”看起来与“客户端一直在请求授权”一模一样。
     */
    @Bean
    OAuth2TokenGenerator<? extends OAuth2Token> mcpTokenGenerator(JWKSource<SecurityContext> jwkSource,
            OAuth2TokenCustomizer<JwtEncodingContext> jwtCustomizer) {
        JwtGenerator jwtGenerator = new JwtGenerator(new NimbusJwtEncoder(jwkSource));
        jwtGenerator.setJwtCustomizer(jwtCustomizer);
        OAuth2TokenGenerator<? extends OAuth2Token> delegate = new DelegatingOAuth2TokenGenerator(
                jwtGenerator,
                new OAuth2AccessTokenGenerator(),
                refreshTokensForPublicClients(new OAuth2RefreshTokenGenerator()));
        return context -> {
            OAuth2Token token = delegate.generate(context);
            log.debug("generate token type={} client={} grantTypes={} -> {}",
                    context.getTokenType() == null ? "null" : context.getTokenType().getValue(),
                    context.getRegisteredClient().getClientId(),
                    context.getRegisteredClient().getAuthorizationGrantTypes(),
                    token == null ? "null" : token.getClass().getSimpleName());
            return token;
        };
    }

    /**
     * 也向公开客户端签发刷新令牌。
     *
     * <p>Spring Security 出于设计拒绝这么做：当客户端在授权码授权中以
     * {@link ClientAuthenticationMethod#NONE} 完成认证时，{@code OAuth2RefreshTokenGenerator} 会返回
     * {@code null}，理由是公开客户端无法保护持有者凭证。
     *
     * <p>每个 MCP 客户端都是公开客户端，而本服务器的访问令牌只存活五分钟。没有刷新令牌，
     * 桌面或 CLI Agent 就得每五分钟把用户再送一次浏览器，这正是实践中“客户端老是让我重新认证”的样子。
     * PKCE 仍然保护授权码兑换，而刷新令牌只会到达完成兑换的那个客户端。
     *
     * <p>TTL 来自客户端自己的 {@code TokenSettings}，所以之后切换
     * {@code reuseRefreshTokens(false)} 就能获得轮换，无需改动这里的代码。
     */
    private static OAuth2TokenGenerator<OAuth2RefreshToken> refreshTokensForPublicClients(
            OAuth2TokenGenerator<OAuth2RefreshToken> delegate) {

        StringKeyGenerator keys = new Base64StringKeyGenerator(Base64.getUrlEncoder().withoutPadding(), 96);

        return context -> {
            OAuth2RefreshToken generated = delegate.generate(context);
            if (generated != null) {
                return generated;
            }
            if (!OAuth2TokenType.REFRESH_TOKEN.equals(context.getTokenType())) {
                return null;
            }
            Instant issuedAt = Instant.now();
            Instant expiresAt = issuedAt
                    .plus(context.getRegisteredClient().getTokenSettings().getRefreshTokenTimeToLive());
            log.debug("issuing a refresh token to public client {}", context.getRegisteredClient().getClientId());
            return new OAuth2RefreshToken(keys.generateKey(), issuedAt, expiresAt);
        };
    }

    /**
     * RFC 8707 受众（aud）绑定，采用适合“单个部署拥有若干种自身地址写法”的形态：
     * 每个访问令牌的 {@code aud} 中携带 {@code app.security.resource-uris} 的<em>全部</em>取值，
     * 资源服务器接受与其中任意一个匹配的令牌。
     *
     * <p>为什么用集合而不是单个值：客户端对回环地址的写法并不一致
     * （{@code localhost} 与 {@code 127.0.0.1}），而严格的单值比较会把这种写法差异
     * 变成难以诊断的 401。
     */
    @Bean
    OAuth2TokenCustomizer<JwtEncodingContext> mcpTokenCustomizer(McpAuthProperties properties) {
        List<String> audiences = List.copyOf(properties.resourceUris());
        return context -> {
            if (OAuth2TokenType.ACCESS_TOKEN.equals(context.getTokenType())) {
                context.getClaims().audience(audiences);
            }
        };
    }

    /**
     * 动态客户端注册的校验。
     *
     * <p>Spring Security 的默认校验器会拒绝任何携带 {@code scope} 的注册
     * （"scope must not be set during Dynamic Client Registration"）。而 MCP 客户端确实会发送
     * 它们从受保护资源元数据中读到的作用域，所以这一条规则被去掉。对安全真正重要的部分保留：
     * 重定向 URI（包括任意端口上的回环地址）和 JWK set URI 仍然会被校验。
     *
     * <p>过于宽泛的 scope 请求不在这里拒绝，而是在
     * {@link #mcpRegisteredClientConverter(McpAuthProperties)} 中被收敛。
     */
    @Bean
    Consumer<OAuth2ClientRegistrationAuthenticationContext> dynamicClientRegistrationValidator() {
        return OAuth2ClientRegistrationAuthenticationValidator.DEFAULT_REDIRECT_URI_VALIDATOR
                .andThen(OAuth2ClientRegistrationAuthenticationValidator.DEFAULT_JWK_SET_URI_VALIDATOR);
    }

    /**
     * 把通过校验的注册请求转换成实际被存储的客户端：
     *
     * <ul>
     *   <li>作用域被收敛到 {@code app.security.scopes} —— 未申请任何作用域就注册的客户端会拿到
     *       全部作用域，这样它在授权时仍能请求这些作用域；</li>
     *   <li>始终要求 PKCE，动态注册不能成为绕过它的途径；</li>
     *   <li>没有授权确认页，因为本演示不授予任何与作用域相关的特权。</li>
     * </ul>
     */
    @Bean
    Converter<OAuth2ClientRegistration, RegisteredClient> mcpRegisteredClientConverter(McpAuthProperties properties) {
        OAuth2ClientRegistrationRegisteredClientConverter delegate = new OAuth2ClientRegistrationRegisteredClientConverter();
        Set<String> supportedScopes = Set.copyOf(properties.scopes());
        return registration -> {
            RegisteredClient converted = delegate.convert(registration);
            Set<String> requested = converted.getScopes();
            Set<String> effective = requested.isEmpty()
                    ? supportedScopes
                    : requested.stream()
                            .filter(supportedScopes::contains)
                            .collect(Collectors.toCollection(LinkedHashSet::new));
            if (effective.isEmpty()) {
                effective = supportedScopes;
            }
            Set<String> granted = effective;
            return RegisteredClient.from(converted)
                    .scopes(scopes -> {
                        scopes.clear();
                        scopes.addAll(granted);
                    })
                    .tokenSettings(refreshTokenRotation())
                    .clientSettings(ClientSettings.builder()
                            .requireProofKey(true)
                            .requireAuthorizationConsent(false)
                            .build())
                    .build();
        };
    }
}
