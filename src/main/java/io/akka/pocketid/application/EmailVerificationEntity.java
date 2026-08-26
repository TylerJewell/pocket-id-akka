package io.akka.pocketid.application;

import akka.javasdk.annotations.Component;
import akka.javasdk.keyvalueentity.KeyValueEntity;

/** emailverification — a pending email-verification token, keyed by user id (one in flight at a
 * time per user, matching the source's actor-per-user state). */
@Component(id = "email-verification")
public class EmailVerificationEntity extends KeyValueEntity<EmailVerificationEntity.State> {

  public record State(String userId, String token, String targetEmail, long expiresAtMillis) {
    public boolean isEmpty() { return token == null; }
  }

  public record Issue(String userId, String token, String targetEmail, long expiresAtMillis) {}

  public enum VerifyResult { OK, NOT_FOUND, EXPIRED, EMAIL_MISMATCH }

  public record VerifyOutcome(VerifyResult result, String targetEmail) {}

  @Override
  public State emptyState() {
    return new State(null, null, null, 0);
  }

  public Effect<State> issue(Issue cmd) {
    var s = new State(cmd.userId(), cmd.token(), cmd.targetEmail(), cmd.expiresAtMillis());
    return effects().updateState(s).thenReply(s);
  }

  public record Verify(String presentedToken, String currentUserEmail, long nowMillis) {}

  public Effect<VerifyOutcome> verify(Verify cmd) {
    var s = currentState();
    if (s.isEmpty() || !s.token().equals(cmd.presentedToken())) {
      return effects().reply(new VerifyOutcome(VerifyResult.NOT_FOUND, null));
    }
    if (cmd.nowMillis() >= s.expiresAtMillis()) {
      return effects().deleteEntity().thenReply(new VerifyOutcome(VerifyResult.EXPIRED, null));
    }
    // The user's current email must still match what the token was issued for, or a stale link
    // could verify an email the user has since changed away from.
    boolean matches = s.targetEmail() != null && s.targetEmail().equals(cmd.currentUserEmail());
    if (!matches) {
      return effects().reply(new VerifyOutcome(VerifyResult.EMAIL_MISMATCH, null));
    }
    return effects().deleteEntity().thenReply(new VerifyOutcome(VerifyResult.OK, s.targetEmail()));
  }

  public Effect<String> discard() {
    return effects().deleteEntity().thenReply("ok");
  }
}
