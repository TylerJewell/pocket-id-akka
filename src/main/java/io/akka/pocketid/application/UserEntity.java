package io.akka.pocketid.application;

import akka.javasdk.annotations.Component;
import akka.javasdk.keyvalueentity.KeyValueEntity;
import io.akka.pocketid.domain.User;
import java.util.List;

/** A managed user, keyed by user id — user_service.go. */
@Component(id = "user")
public class UserEntity extends KeyValueEntity<User> {

  public record Create(
      String id, String username, String email, String firstName, String lastName,
      String displayName, boolean isAdmin, List<String> groupIds, long nowMillis) {}

  public record UpdateProfile(
      String username, String email, String firstName, String lastName, String displayName,
      String locale, long nowMillis) {}

  public record SetGroups(List<String> groupIds, long nowMillis) {}

  public record SetDisabled(boolean disabled, long nowMillis) {}

  public record SetAdmin(boolean isAdmin, long nowMillis) {}

  public record VerifyEmail(long nowMillis) {}

  @Override
  public User emptyState() {
    return new User(null, null, null, false, null, null, null, false, null, false, null, List.of(), 0, 0);
  }

  public Effect<User> create(Create cmd) {
    if (currentState().id() != null) {
      return effects().error("User already exists");
    }
    var user = new User(
        cmd.id(), cmd.username(), cmd.email(), false, cmd.firstName(), cmd.lastName(),
        cmd.displayName(), cmd.isAdmin(), null, false, null, cmd.groupIds(), cmd.nowMillis(), cmd.nowMillis());
    return effects().updateState(user).thenReply(user);
  }

  public Effect<User> updateProfile(UpdateProfile cmd) {
    if (currentState().id() == null) return effects().error("User not found");
    var updated = currentState().withProfile(cmd.username(), cmd.email(), cmd.firstName(), cmd.lastName(), cmd.displayName(), cmd.locale(), cmd.nowMillis());
    return effects().updateState(updated).thenReply(updated);
  }

  public Effect<User> setGroups(SetGroups cmd) {
    if (currentState().id() == null) return effects().error("User not found");
    var updated = currentState().withGroups(cmd.groupIds(), cmd.nowMillis());
    return effects().updateState(updated).thenReply(updated);
  }

  public Effect<User> setDisabled(SetDisabled cmd) {
    if (currentState().id() == null) return effects().error("User not found");
    var updated = currentState().withDisabled(cmd.disabled(), cmd.nowMillis());
    return effects().updateState(updated).thenReply(updated);
  }

  public Effect<User> setAdmin(SetAdmin cmd) {
    if (currentState().id() == null) return effects().error("User not found");
    var updated = currentState().withAdmin(cmd.isAdmin(), cmd.nowMillis());
    return effects().updateState(updated).thenReply(updated);
  }

  public Effect<User> verifyEmail(VerifyEmail cmd) {
    if (currentState().id() == null) return effects().error("User not found");
    var updated = currentState().withEmailVerified(true, cmd.nowMillis());
    return effects().updateState(updated).thenReply(updated);
  }

  public Effect<User> get() {
    return effects().reply(currentState());
  }

  public Effect<String> delete() {
    return effects().deleteEntity().thenReply("ok");
  }
}
