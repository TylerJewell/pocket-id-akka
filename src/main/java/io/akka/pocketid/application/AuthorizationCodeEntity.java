package io.akka.pocketid.application;

import akka.javasdk.annotations.Component;
import akka.javasdk.keyvalueentity.KeyValueEntity;
import io.akka.pocketid.domain.AuthorizationCodeState;
import java.util.List;

/**
 * One authorization code, keyed by the code itself — SPEC-001 §3 rules 5, 7, 8, 9. The entity id
 * serialises every read-modify-write against a given code, which is what makes "exchangeable
 * exactly once" (rule 8) enforceable without extra locking.
 */
@Component(id = "authorization-code")
public class AuthorizationCodeEntity extends KeyValueEntity<AuthorizationCodeState> {

  public record Issue(
      String code,
      String clientId,
      String redirectUri,
      String scope,
      String subject,
      String nonce,
      String codeChallenge,
      long expiresAtMillis) {}

  public enum ConsumeResult {
    OK,
    NOT_FOUND,
    EXPIRED,
    ALREADY_CONSUMED
  }

  public record Consume(long nowMillis) {}

  public record ConsumeOutcome(
      ConsumeResult result, AuthorizationCodeState state, List<String> revokedRefreshTokens) {}

  public record MarkExchanged(String issuedRefreshToken) {}

  @Override
  public AuthorizationCodeState emptyState() {
    return AuthorizationCodeState.empty();
  }

  public Effect<String> issue(Issue command) {
    var state =
        new AuthorizationCodeState(
            command.code(),
            command.clientId(),
            command.redirectUri(),
            command.scope(),
            command.subject(),
            command.nonce(),
            command.codeChallenge(),
            command.expiresAtMillis(),
            false,
            List.of());
    return effects().updateState(state).thenReply(command.code());
  }

  /**
   * Validates and consumes the code in one step. A code found already consumed is left
   * unchanged in storage (its {@code issuedRefreshTokens} is the caller's revocation list, per
   * rule 8) rather than deleted, so a second replay is still detectable as ALREADY_CONSUMED
   * rather than NOT_FOUND.
   */
  public Effect<ConsumeOutcome> consume(Consume command) {
    var state = currentState();
    if (state.isEmpty()) {
      return effects().reply(new ConsumeOutcome(ConsumeResult.NOT_FOUND, state, List.of()));
    }
    if (state.consumed()) {
      return effects()
          .reply(new ConsumeOutcome(ConsumeResult.ALREADY_CONSUMED, state, state.issuedRefreshTokens()));
    }
    if (state.isExpired(command.nowMillis())) {
      return effects().reply(new ConsumeOutcome(ConsumeResult.EXPIRED, state, List.of()));
    }
    return effects().reply(new ConsumeOutcome(ConsumeResult.OK, state, List.of()));
  }

  /** Records which refresh token an exchange produced, so a future replay can revoke it. */
  public Effect<String> markExchanged(MarkExchanged command) {
    var state = currentState().consumedWithRefreshToken(command.issuedRefreshToken());
    return effects().updateState(state).thenReply("ok");
  }
}
