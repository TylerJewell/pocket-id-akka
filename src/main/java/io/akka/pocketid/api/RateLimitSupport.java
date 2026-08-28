package io.akka.pocketid.api;

import akka.http.javadsl.model.HttpHeader;
import akka.http.javadsl.model.HttpResponse;
import akka.http.javadsl.model.StatusCodes;
import akka.javasdk.client.ComponentClient;
import akka.javasdk.http.HttpResponses;
import akka.javasdk.http.RequestContext;
import io.akka.pocketid.application.AppConfigEntity;
import io.akka.pocketid.application.RateLimitEntity;
import io.akka.pocketid.application.RateLimitPolicies;
import java.time.Instant;
import java.util.Map;

/** `middleware.RateLimit`'s equivalent: one token bucket per (policy, client IP), fails open on
 * a limiter error the way the source's `Allow` call does (rate_limit.go), and is skippable
 * entirely via {@code disableRateLimiting} — the source's own escape hatch, exposed here as an
 * app-config key rather than an env var since that is how every other admin-tunable setting in
 * this port is exposed (AppConfigEndpoint). */
public final class RateLimitSupport {
  private RateLimitSupport() {}

  /** Returns {@code null} if the request may proceed, or a 429 response to return as-is. */
  public static HttpResponse check(ComponentClient cc, RequestContext ctx, String policyName) {
    var config = cc.forKeyValueEntity("singleton").method(AppConfigEntity::get).invoke();
    if (Boolean.parseBoolean(config.getOrDefault("disableRateLimiting", "false"))) return null;

    var policy = RateLimitPolicies.POLICIES.get(policyName);
    if (policy == null) throw new IllegalArgumentException("unknown rate-limit policy: " + policyName);

    String ip = ctx.requestHeader("X-Forwarded-For").map(HttpHeader::value).orElse("unknown");
    boolean allowed = cc.forKeyValueEntity("ratelimit:" + policyName + ":" + ip).method(RateLimitEntity::tryConsume)
        .invoke(new RateLimitEntity.TryConsume(policy.capacity(), policy.refillPerMillis(), Instant.now().toEpochMilli()));

    if (allowed) return null;
    return HttpResponses.ok(Map.of("error", "Too many requests. Please try again later.")).withStatus(StatusCodes.TOO_MANY_REQUESTS);
  }
}
