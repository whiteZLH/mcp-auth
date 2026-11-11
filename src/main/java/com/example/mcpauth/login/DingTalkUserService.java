package com.example.mcpauth.login;

import java.util.List;
import java.util.Map;

import org.springframework.core.ParameterizedTypeReference;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.oauth2.client.userinfo.OAuth2UserRequest;
import org.springframework.security.oauth2.client.userinfo.OAuth2UserService;
import org.springframework.security.oauth2.core.OAuth2AuthenticationException;
import org.springframework.security.oauth2.core.OAuth2Error;
import org.springframework.security.oauth2.core.OAuth2ErrorCodes;
import org.springframework.security.oauth2.core.user.DefaultOAuth2User;
import org.springframework.security.oauth2.core.user.OAuth2User;
import org.springframework.web.client.RestClient;
import org.springframework.web.client.RestClientException;

/**
 * 加载刚登录用户的钉钉资料。
 *
 * <p>与默认 {@code DefaultOAuth2UserService} 有两处不同：访问令牌放在
 * {@code x-acs-dingtalk-access-token} 中传递（而不是 {@code Authorization: Bearer}），端点是
 * {@code /v1.0/contact/users/me}。
 *
 * <p>钉钉返回的所有内容（{@code nick}、{@code unionId}、{@code openId}、{@code avatarUrl}、
 * {@code mobile}、{@code email}）都作为用户属性保留，以便据此推导主体名称以及后续的任何分组映射。
 */
public final class DingTalkUserService implements OAuth2UserService<OAuth2UserRequest, OAuth2User> {

    /** 钉钉要求使用的请求头，用来替代标准的 bearer 请求头。 */
    static final String ACCESS_TOKEN_HEADER = "x-acs-dingtalk-access-token";

    private final RestClient restClient;
    private final String userInfoUri;
    private final String userNameAttribute;

    public DingTalkUserService(RestClient restClient, String userInfoUri, String userNameAttribute) {
        this.restClient = restClient;
        this.userInfoUri = userInfoUri;
        this.userNameAttribute = userNameAttribute;
    }

    @Override
    public OAuth2User loadUser(OAuth2UserRequest userRequest) throws OAuth2AuthenticationException {
        String accessToken = userRequest.getAccessToken().getTokenValue();

        Map<String, Object> attributes;
        try {
            attributes = this.restClient.get()
                    .uri(this.userInfoUri)
                    .header(ACCESS_TOKEN_HEADER, accessToken)
                    .retrieve()
                    .body(new ParameterizedTypeReference<Map<String, Object>>() {
                    });
        }
        catch (RestClientException ex) {
            throw new OAuth2AuthenticationException(new OAuth2Error(OAuth2ErrorCodes.INVALID_TOKEN,
                    "DingTalk user info request failed: " + ex.getMessage(), null), ex);
        }

        if (attributes == null || attributes.get(this.userNameAttribute) == null) {
            throw new OAuth2AuthenticationException(new OAuth2Error(OAuth2ErrorCodes.INVALID_TOKEN,
                    "DingTalk user info response has no '" + this.userNameAttribute + "'", null));
        }

        List<GrantedAuthority> authorities = List.of(new SimpleGrantedAuthority("ROLE_USER"));
        return new DefaultOAuth2User(authorities, attributes, this.userNameAttribute);
    }
}
