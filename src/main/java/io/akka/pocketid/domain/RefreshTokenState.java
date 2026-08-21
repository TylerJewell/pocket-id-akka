package io.akka.pocketid.domain;

/** One issued refresh token — SPEC-001 §2, §3 rule 14 (rotate on use, reject reuse). */
public record RefreshTokenState(
    String token,
    String clientId,
    String subject,
    String scope,
    long expiresAtMillis,
    boolean revoked) {

  public static RefreshTokenState empty() {
    return new RefreshTokenState(null, null, null, null, 0, false);
  }

  public boolean isEmpty() {
    return token == null;
  }

  public boolean isUsable(long nowMillis) {
    return !isEmpty() && !revoked && nowMillis < expiresAtMillis;
  }
}
