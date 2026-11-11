package com.example.mcpauth.oauth;

import java.time.Duration;
import java.time.Instant;

import org.junit.jupiter.api.Test;

import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.core.ClientAuthenticationMethod;
import org.springframework.security.oauth2.core.OAuth2RefreshToken;
import org.springframework.security.oauth2.server.authorization.InMemoryOAuth2AuthorizationService;
import org.springframework.security.oauth2.server.authorization.OAuth2Authorization;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * 刷新令牌的绝对生命周期是令牌流程中唯一无法用黑盒 HTTP 测试检验的部分——那需要等上好几天，
 * 因此在单元测试层面验证。
 */
class AbsoluteRefreshTokenLifetimeTests {

    private static final Instant NOW = Instant.parse("2026-11-10T12:00:00Z");

    @Test
    void firstIssuanceIsRecordedOnceAndSurvivesRotation() {
        OAuth2Authorization first = authorization(refreshToken("first", NOW.minusSeconds(3600)));
        OAuth2Authorization stamped = FirstIssuanceTrackingAuthorizationService.stampIfFirstIssuance(first);

        assertThat((Instant) stamped.getAttribute(FirstIssuanceTrackingAuthorizationService.FIRST_REFRESH_ISSUED_AT))
                .isEqualTo(NOW.minusSeconds(3600));

        // 之后发生一次轮换：新的刷新令牌、同一个授权。必须保留最初的时间戳。
        OAuth2Authorization rotated = OAuth2Authorization.from(stamped)
                .refreshToken(refreshToken("rotated", NOW))
                .build();
        OAuth2Authorization reStamped = FirstIssuanceTrackingAuthorizationService.stampIfFirstIssuance(rotated);

        assertThat((Instant) reStamped.getAttribute(FirstIssuanceTrackingAuthorizationService.FIRST_REFRESH_ISSUED_AT))
                .isEqualTo(NOW.minusSeconds(3600));
    }

    @Test
    void grantInsideTheLifetimeIsStillRefreshable() {
        OAuth2Authorization authorization = FirstIssuanceTrackingAuthorizationService
                .stampIfFirstIssuance(authorization(refreshToken("t", NOW.minus(Duration.ofDays(29)))));

        assertThat(AbsoluteLifetimeRefreshTokenAuthenticationProvider
                .exceedsAbsoluteLifetime(authorization, Duration.ofDays(30), NOW)).isFalse();
    }

    @Test
    void grantBeyondTheLifetimeIsRejected() {
        OAuth2Authorization authorization = FirstIssuanceTrackingAuthorizationService
                .stampIfFirstIssuance(authorization(refreshToken("t", NOW.minus(Duration.ofDays(31)))));

        assertThat(AbsoluteLifetimeRefreshTokenAuthenticationProvider
                .exceedsAbsoluteLifetime(authorization, Duration.ofDays(30), NOW)).isTrue();
    }

    @Test
    void rotationAloneWouldNeverExpire() {
        // 这一上限的意义所在：刚轮换出的令牌看起来是全新的，正因如此才必须把首次签发的
        // 时间一并传递下去。
        OAuth2Authorization rotatedOnly = authorization(refreshToken("rotated", NOW));

        assertThat(AbsoluteLifetimeRefreshTokenAuthenticationProvider
                .exceedsAbsoluteLifetime(rotatedOnly, Duration.ofDays(30), NOW)).isFalse();

        OAuth2Authorization rotatedButOldGrant = FirstIssuanceTrackingAuthorizationService.stampIfFirstIssuance(
                OAuth2Authorization.from(rotatedOnly)
                        .attribute(FirstIssuanceTrackingAuthorizationService.FIRST_REFRESH_ISSUED_AT,
                                NOW.minus(Duration.ofDays(31)))
                        .build());

        assertThat(AbsoluteLifetimeRefreshTokenAuthenticationProvider
                .exceedsAbsoluteLifetime(rotatedButOldGrant, Duration.ofDays(30), NOW)).isTrue();
    }

    @Test
    void zeroLifetimeDisablesTheCap() {
        OAuth2Authorization authorization = FirstIssuanceTrackingAuthorizationService
                .stampIfFirstIssuance(authorization(refreshToken("t", NOW.minus(Duration.ofDays(365)))));

        assertThat(AbsoluteLifetimeRefreshTokenAuthenticationProvider
                .exceedsAbsoluteLifetime(authorization, Duration.ZERO, NOW)).isFalse();
    }

    @Test
    void wrapperPersistsTheTimestampThroughTheUnderlyingStore() {
        InMemoryOAuth2AuthorizationService delegate = new InMemoryOAuth2AuthorizationService();
        FirstIssuanceTrackingAuthorizationService tracking = new FirstIssuanceTrackingAuthorizationService(delegate);
        OAuth2Authorization authorization = authorization(refreshToken("token", NOW.minusSeconds(60)));

        tracking.save(authorization);

        OAuth2Authorization loaded = delegate.findById(authorization.getId());
        assertThat((Instant) loaded.getAttribute(FirstIssuanceTrackingAuthorizationService.FIRST_REFRESH_ISSUED_AT))
                .isEqualTo(NOW.minusSeconds(60));
    }

    private static OAuth2Authorization authorization(OAuth2RefreshToken refreshToken) {
        RegisteredClient client = RegisteredClient.withId("client-1")
                .clientId("mcp-cli")
                .clientAuthenticationMethod(ClientAuthenticationMethod.NONE)
                .authorizationGrantType(AuthorizationGrantType.AUTHORIZATION_CODE)
                .redirectUri("http://127.0.0.1:8080/callback")
                .build();
        return OAuth2Authorization.withRegisteredClient(client)
                .id("authorization-1")
                .principalName("user")
                .authorizationGrantType(AuthorizationGrantType.AUTHORIZATION_CODE)
                .refreshToken(refreshToken)
                .build();
    }

    private static OAuth2RefreshToken refreshToken(String value, Instant issuedAt) {
        return new OAuth2RefreshToken(value, issuedAt, issuedAt.plus(Duration.ofHours(1)));
    }
}
