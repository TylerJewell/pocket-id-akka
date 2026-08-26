package io.akka.pocketid.application;

import akka.javasdk.annotations.Component;
import akka.javasdk.keyvalueentity.KeyValueEntity;

/**
 * webauthn — a short-lived server-generated challenge for one in-flight registration or login
 * ceremony, keyed by a random session id the client carries between /start and /finish. TTL is
 * enforced by the caller (60s, matching the source's go-webauthn timeout) rather than by the
 * entity itself, since a KeyValueEntity has no built-in expiry.
 */
@Component(id = "webauthn-challenge")
public class WebAuthnChallengeEntity extends KeyValueEntity<WebAuthnChallengeEntity.State> {

  public record State(String sessionId, String challengeBase64, String userId, boolean forRegistration, long expiresAtMillis) {
    public boolean isEmpty() { return sessionId == null; }
  }

  public record Start(String sessionId, String challengeBase64, String userId, boolean forRegistration, long expiresAtMillis) {}

  @Override
  public State emptyState() {
    return new State(null, null, null, false, 0);
  }

  public Effect<State> start(Start cmd) {
    var state = new State(cmd.sessionId(), cmd.challengeBase64(), cmd.userId(), cmd.forRegistration(), cmd.expiresAtMillis());
    return effects().updateState(state).thenReply(state);
  }

  public Effect<State> get() {
    return effects().reply(currentState());
  }

  public Effect<String> consume() {
    return effects().deleteEntity().thenReply("ok");
  }
}
