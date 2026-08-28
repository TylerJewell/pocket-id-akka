package io.akka.pocketid.application;

import akka.javasdk.annotations.Component;
import akka.javasdk.keyvalueentity.KeyValueEntity;

/**
 * A per-(policy, client-IP) token bucket — the entity form of `rate_limit.go`'s Francis-actor
 * limiters. One instance per key (see {@link RateLimitPolicies} for the id format), so every
 * policy's buckets stay isolated from every other policy's, matching the source's comment that
 * "every IP is limited independently and per-route limits stay isolated from each other." Holds
 * no durable value worth keeping across a restart (an empty bucket is a full bucket), the same
 * reasoning the source gives for registering its limiters in every environment rather than only
 * where a durable store is configured.
 */
@Component(id = "rate-limit")
public class RateLimitEntity extends KeyValueEntity<RateLimitEntity.State> {

  public record State(double tokens, long lastRefillMillis) {}

  public record TryConsume(double capacity, double refillPerMillis, long nowMillis) {}

  @Override
  public State emptyState() {
    return new State(-1, 0); // -1 marks "never filled" so the first call starts at a full bucket
  }

  /** Refills by elapsed time at {@code refillPerMillis}, capped at {@code capacity}, then takes
   * one token if available. Fails open on a state this policy's capacity shrank underneath
   * (never observed in practice, but a shrinking capacity should not wedge a bucket negative). */
  public Effect<Boolean> tryConsume(TryConsume cmd) {
    double tokens = currentState().tokens() < 0 ? cmd.capacity() : currentState().tokens();
    long elapsed = Math.max(0, cmd.nowMillis() - currentState().lastRefillMillis());
    tokens = Math.min(cmd.capacity(), tokens + elapsed * cmd.refillPerMillis());
    boolean allowed = tokens >= 1.0;
    if (allowed) tokens -= 1.0;
    return effects().updateState(new State(tokens, cmd.nowMillis())).thenReply(allowed);
  }
}
