package io.akka.pocketid.application;

import java.util.Map;

/** `rate_limit.go`'s {@code RateLimitPolicies()} — one token bucket per named policy, each
 * keyed independently per client IP (see {@link RateLimitEntity}). Capacity is the burst size;
 * {@code refillPerMillis} is rate-per-window converted to a per-millisecond refill rate so
 * {@link RateLimitEntity#tryConsume} can work in wall-clock time instead of ticking windows. */
public final class RateLimitPolicies {
  private RateLimitPolicies() {}

  public record Policy(double capacity, double refillPerMillis) {}

  private static Policy of(double rate, double perMillis, double burst) {
    return new Policy(burst, rate / perMillis);
  }

  public static final Map<String, Policy> POLICIES = Map.ofEntries(
      Map.entry("api", of(100, 1_000, 300)),
      Map.entry("signup", of(2, 60_000, 10)),
      Map.entry("webauthn-login", of(1, 5_000, 10)),
      Map.entry("webauthn-reauthenticate", of(1, 10_000, 5)),
      Map.entry("one-time-access-token", of(1, 10_000, 5)),
      Map.entry("one-time-access-email", of(2, 600_000, 5)),
      Map.entry("device-login-create", of(1, 10_000, 5)),
      Map.entry("device-login-exchange", of(1, 2_000, 10)),
      Map.entry("device-login-verification", of(1, 10_000, 5)),
      Map.entry("send-email-verification", of(2, 600_000, 1)),
      Map.entry("verify-email", of(1, 10_000, 5)),
      Map.entry("internal", of(20, 1_000, 20)));
}
