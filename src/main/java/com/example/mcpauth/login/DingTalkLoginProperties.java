package com.example.mcpauth.login;

import org.springframework.boot.context.properties.ConfigurationProperties;

/**
 * 钉钉登录配置。
 *
 * <p>钉钉的网页登录是 OAuth 2.0，但不是 OpenID Connect：没有发现文档，没有
 * {@code id_token}，令牌请求是 JSON 而不是表单编码，用户信息端点需要的是
 * {@code x-acs-dingtalk-access-token} 而不是 {@code Authorization: Bearer}。正因如此，
 * 下面显式配置了各端点和属性映射，而不是通过 {@code issuer-uri}。
 *
 * @param clientId     钉钉应用 AppKey；留空时整个钉钉登录被关闭，演示用的表单登录仍是唯一入口
 * @param clientSecret 钉钉应用 AppSecret
 * @param authorizeUri 授权端点（钉钉要求 {@code prompt=consent}，已在此处添加）
 * @param tokenUri     令牌端点，期望 JSON 请求体
 * @param userInfoUri  用户信息端点，调用时把 {@code unionId} 路径段设为 {@code me}
 * @param userNameAttribute 用作主体名称的属性
 */
@ConfigurationProperties(prefix = "app.login.dingtalk")
public record DingTalkLoginProperties(
        String clientId,
        String clientSecret,
        String authorizeUri,
        String tokenUri,
        String userInfoUri,
        String userNameAttribute) {

    public DingTalkLoginProperties {
        if (authorizeUri == null || authorizeUri.isBlank()) {
            authorizeUri = "https://login.dingtalk.com/oauth2/auth?prompt=consent";
        }
        if (tokenUri == null || tokenUri.isBlank()) {
            tokenUri = "https://api.dingtalk.com/v1.0/oauth2/userAccessToken";
        }
        if (userInfoUri == null || userInfoUri.isBlank()) {
            userInfoUri = "https://api.dingtalk.com/v1.0/contact/users/me";
        }
        if (userNameAttribute == null || userNameAttribute.isBlank()) {
            userNameAttribute = "unionId";
        }
    }

    public boolean isConfigured() {
        return clientId != null && !clientId.isBlank() && clientSecret != null && !clientSecret.isBlank();
    }
}
