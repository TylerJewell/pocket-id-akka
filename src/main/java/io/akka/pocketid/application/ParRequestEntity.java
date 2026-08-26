package io.akka.pocketid.application;

import akka.javasdk.annotations.Component;
import akka.javasdk.keyvalueentity.KeyValueEntity;

/** oidc — a Pushed Authorization Request, keyed by the {@code request_uri} it was issued under.
 * Single-use: {@code /authorize} consumes it once, exactly like an authorization code. */
@Component(id = "par-request")
public class ParRequestEntity extends KeyValueEntity<ParRequestEntity.State> {

  public record State(
      String requestUri, String clientId, String redirectUri, String responseType, String scope,
      String state_, String nonce, String codeChallenge, String codeChallengeMethod, long expiresAtMillis, boolean consumed) {
    public boolean isEmpty() { return requestUri == null; }
  }

  public record Push(
      String requestUri, String clientId, String redirectUri, String responseType, String scope,
      String state_, String nonce, String codeChallenge, String codeChallengeMethod, long expiresAtMillis) {}

  @Override
  public State emptyState() {
    return new State(null, null, null, null, null, null, null, null, null, 0, false);
  }

  public Effect<State> push(Push cmd) {
    var s = new State(cmd.requestUri(), cmd.clientId(), cmd.redirectUri(), cmd.responseType(), cmd.scope(),
        cmd.state_(), cmd.nonce(), cmd.codeChallenge(), cmd.codeChallengeMethod(), cmd.expiresAtMillis(), false);
    return effects().updateState(s).thenReply(s);
  }

  public Effect<State> consume() {
    if (currentState().isEmpty() || currentState().consumed()) return effects().reply(currentState());
    var s = currentState();
    var updated = new State(s.requestUri(), s.clientId(), s.redirectUri(), s.responseType(), s.scope(),
        s.state_(), s.nonce(), s.codeChallenge(), s.codeChallengeMethod(), s.expiresAtMillis(), true);
    return effects().updateState(updated).thenReply(s); // return pre-consumption snapshot
  }
}
