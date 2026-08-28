package io.akka.pocketid.application;

import static org.assertj.core.api.Assertions.assertThat;

import akka.javasdk.testkit.TestKitSupport;
import org.junit.jupiter.api.Test;

/** `rate_limit.go`'s token bucket, ported as {@link RateLimitEntity} — one bucket per
 * (policy, IP), refilling by elapsed wall-clock time, capped at the policy's burst. */
public class RateLimitIntegrationTest extends TestKitSupport {

  @Test
  void bucketAllowsUpToBurstThenBlocksUntilRefill() {
    var cmd = new RateLimitEntity.TryConsume(3, 0.0, 1_000L); // capacity 3, no refill, fixed clock
    String key = "ratelimit-test:" + java.util.UUID.randomUUID();

    assertThat(componentClient.forKeyValueEntity(key).method(RateLimitEntity::tryConsume).invoke(cmd)).isTrue();
    assertThat(componentClient.forKeyValueEntity(key).method(RateLimitEntity::tryConsume).invoke(cmd)).isTrue();
    assertThat(componentClient.forKeyValueEntity(key).method(RateLimitEntity::tryConsume).invoke(cmd)).isTrue();
    // burst of 3 exhausted, no time has elapsed (same nowMillis) to refill
    assertThat(componentClient.forKeyValueEntity(key).method(RateLimitEntity::tryConsume).invoke(cmd)).isFalse();

    // elapsed time at a refill rate of 1 token/ms brings it back above 1
    var refilled = new RateLimitEntity.TryConsume(3, 1.0, 1_010L);
    assertThat(componentClient.forKeyValueEntity(key).method(RateLimitEntity::tryConsume).invoke(refilled)).isTrue();
  }

  @Test
  void oneTimeAccessEmailEndpointReturns429AfterItsBurstOfFive() {
    var request = new io.akka.pocketid.api.SignupEndpoint.OneTimeEmailRequest("nobody@example.com", null);
    // Feature itself is disabled by default (emailOneTimeAccessAsUnauthenticatedEnabled=false),
    // so every call replies 403 regardless of outcome -- this test only exercises the rate
    // limiter wrapping the endpoint (applied before the feature-enabled check), not the
    // email-issuing behavior underneath it.
    for (int i = 0; i < 5; i++) {
      var response = httpClient.POST("/api/one-time-access-email").withRequestBody(request).invoke().httpResponse();
      assertThat(response.status().intValue()).isEqualTo(403);
    }
    var sixth = httpClient.POST("/api/one-time-access-email").withRequestBody(request).invoke().httpResponse();
    assertThat(sixth.status().intValue()).isEqualTo(429);
  }
}
