package io.akka.pocketid.domain;

/**
 * A stand-in for the source's passkey login (SPEC-001 §1 "out of scope" — this port mints the
 * same kind of authenticated session a passkey login would, through {@code POST /login} instead
 * of WebAuthn). Everything downstream of {@code /authorize} treats it identically either way,
 * per question-log row 10.
 */
public record AuthnSessionState(String sessionId, String subject, long authTimeMillis) {

  public static AuthnSessionState empty() {
    return new AuthnSessionState(null, null, 0);
  }

  public boolean isEmpty() {
    return sessionId == null;
  }
}
