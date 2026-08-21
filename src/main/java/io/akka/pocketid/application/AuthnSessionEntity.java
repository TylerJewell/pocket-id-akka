package io.akka.pocketid.application;

import akka.javasdk.annotations.Component;
import akka.javasdk.keyvalueentity.KeyValueEntity;
import io.akka.pocketid.domain.AuthnSessionState;

/** A test-login session, keyed by an opaque session id — the stand-in from SPEC-001 §1. */
@Component(id = "authn-session")
public class AuthnSessionEntity extends KeyValueEntity<AuthnSessionState> {

  public record Create(String sessionId, String subject, long authTimeMillis) {}

  @Override
  public AuthnSessionState emptyState() {
    return AuthnSessionState.empty();
  }

  public Effect<String> create(Create command) {
    var state = new AuthnSessionState(command.sessionId(), command.subject(), command.authTimeMillis());
    return effects().updateState(state).thenReply(command.sessionId());
  }

  public ReadOnlyEffect<AuthnSessionState> get() {
    return effects().reply(currentState());
  }
}
