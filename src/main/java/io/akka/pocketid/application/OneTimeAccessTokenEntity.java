package io.akka.pocketid.application;

import akka.javasdk.annotations.Component;
import akka.javasdk.keyvalueentity.KeyValueEntity;

/** onetimeaccess — a single-use login link/code, keyed by the token itself. */
@Component(id = "one-time-access-token")
public class OneTimeAccessTokenEntity extends KeyValueEntity<OneTimeAccessTokenEntity.State> {

  public record State(String token, String userId, long expiresAtMillis, boolean consumed) {
    public boolean isEmpty() { return token == null; }
  }

  public record Issue(String token, String userId, long expiresAtMillis) {}

  public enum ConsumeResult { OK, NOT_FOUND, EXPIRED, ALREADY_CONSUMED }

  public record ConsumeOutcome(ConsumeResult result, String userId) {}

  @Override
  public State emptyState() {
    return new State(null, null, 0, false);
  }

  public Effect<State> issue(Issue cmd) {
    var s = new State(cmd.token(), cmd.userId(), cmd.expiresAtMillis(), false);
    return effects().updateState(s).thenReply(s);
  }

  public Effect<ConsumeOutcome> consume(long nowMillis) {
    var s = currentState();
    if (s.isEmpty()) return effects().reply(new ConsumeOutcome(ConsumeResult.NOT_FOUND, null));
    if (s.consumed()) return effects().reply(new ConsumeOutcome(ConsumeResult.ALREADY_CONSUMED, null));
    if (nowMillis >= s.expiresAtMillis()) return effects().reply(new ConsumeOutcome(ConsumeResult.EXPIRED, null));
    return effects()
        .updateState(new State(s.token(), s.userId(), s.expiresAtMillis(), true))
        .thenReply(new ConsumeOutcome(ConsumeResult.OK, s.userId()));
  }
}
