package io.akka.pocketid.domain;

import java.util.List;

/**
 * One issued authorization code — SPEC-001 §2, §3 rules 5, 7, 8, 9.
 *
 * <p>{@code revokedRefreshTokens} is empty until the code is replayed after consumption; rule 8
 * requires that replay to revoke every refresh token this code's exchange produced, and the code
 * itself is what remembers which those were.
 */
public record AuthorizationCodeState(
    String code,
    String clientId,
    String redirectUri,
    String scope,
    String subject,
    String nonce,
    String codeChallenge,
    long expiresAtMillis,
    boolean consumed,
    List<String> issuedRefreshTokens) {

  public static AuthorizationCodeState empty() {
    return new AuthorizationCodeState(null, null, null, null, null, null, null, 0, false, List.of());
  }

  public boolean isEmpty() {
    return code == null;
  }

  public boolean isExpired(long nowMillis) {
    return nowMillis >= expiresAtMillis;
  }

  public AuthorizationCodeState consumedWithRefreshToken(String refreshToken) {
    var tokens = new java.util.ArrayList<>(issuedRefreshTokens);
    if (refreshToken != null) tokens.add(refreshToken);
    return new AuthorizationCodeState(
        code, clientId, redirectUri, scope, subject, nonce, codeChallenge, expiresAtMillis, true, tokens);
  }
}
