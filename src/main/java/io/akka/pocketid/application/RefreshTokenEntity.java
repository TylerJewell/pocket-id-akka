package io.akka.pocketid.application;

import akka.javasdk.annotations.Component;
import akka.javasdk.keyvalueentity.KeyValueEntity;
import io.akka.pocketid.domain.RefreshTokenState;

/** One refresh token, keyed by the token itself — SPEC-001 §3 rule 14 (rotate on use). */
@Component(id = "refresh-token")
public class RefreshTokenEntity extends KeyValueEntity<RefreshTokenState> {

  public record Issue(
      String token, String clientId, String subject, String scope, long expiresAtMillis) {}

  public enum RedeemResult {
    OK,
    NOT_FOUND,
    EXPIRED,
    REVOKED
  }

  public record Redeem(long nowMillis) {}

  public record RedeemOutcome(RedeemResult result, RefreshTokenState state) {}

  @Override
  public RefreshTokenState emptyState() {
    return RefreshTokenState.empty();
  }

  public Effect<String> issue(Issue command) {
    var state =
        new RefreshTokenState(
            command.token(),
            command.clientId(),
            command.subject(),
            command.scope(),
            command.expiresAtMillis(),
            false);
    return effects().updateState(state).thenReply(command.token());
  }

  /** Read-only check: does not itself rotate, the caller issues a new token and revokes this one. */
  public ReadOnlyEffect<RedeemOutcome> checkRedeemable(Redeem command) {
    var state = currentState();
    if (state.isEmpty()) return effects().reply(new RedeemOutcome(RedeemResult.NOT_FOUND, state));
    if (state.revoked()) return effects().reply(new RedeemOutcome(RedeemResult.REVOKED, state));
    if (!state.isUsable(command.nowMillis()))
      return effects().reply(new RedeemOutcome(RedeemResult.EXPIRED, state));
    return effects().reply(new RedeemOutcome(RedeemResult.OK, state));
  }

  public Effect<String> revoke() {
    var state = currentState();
    if (state.isEmpty()) return effects().reply("not-found");
    return effects().updateState(new RefreshTokenState(
        state.token(), state.clientId(), state.subject(), state.scope(), state.expiresAtMillis(), true))
        .thenReply("revoked");
  }
}
