package io.akka.pocketid.application;

import akka.javasdk.annotations.Component;
import akka.javasdk.keyvalueentity.KeyValueEntity;
import io.akka.pocketid.domain.SignupToken;
import java.util.List;

/** usersignup — an admin-issued signup token, keyed by the token string itself. */
@Component(id = "signup-token")
public class SignupTokenEntity extends KeyValueEntity<SignupToken> {

  public record Create(String id, String token, long expiresAtMillis, int usageLimit, List<String> userGroupIds, long nowMillis) {}

  @Override
  public SignupToken emptyState() {
    return new SignupToken(null, null, 0, 0, 0, List.of(), 0);
  }

  public Effect<SignupToken> create(Create cmd) {
    var t = new SignupToken(cmd.id(), cmd.token(), cmd.expiresAtMillis(), cmd.usageLimit(), 0, cmd.userGroupIds(), cmd.nowMillis());
    return effects().updateState(t).thenReply(t);
  }

  public Effect<SignupToken> consume() {
    if (currentState().id() == null) return effects().error("Token not found");
    var updated = currentState().consumed();
    return effects().updateState(updated).thenReply(updated);
  }

  public Effect<SignupToken> get() {
    return effects().reply(currentState());
  }

  public Effect<String> delete() {
    return effects().deleteEntity().thenReply("ok");
  }
}
