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

  public record CreateFromLdap(
      String id, String username, String email, String firstName, String lastName,
      String ldapId, long nowMillis) {}

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

  /** `pocket-id import`'s equivalent for one user record: writes the full state a backup
   * captured, rather than re-deriving it through {@link #create}'s narrower invariants (which
   * cannot express an already-verified email, a non-default locale, or an original creation
   * timestamp). Overwrites in place if the id already exists -- {@code deleteEntity()} is
   * permanent in this SDK (AK-00205: "cannot be changed after deletion"), so an import that
   * restores the same id an admin is calling it from must overwrite rather than delete-then-
   * recreate; {@link io.akka.pocketid.api.BackupEndpoint} only hard-deletes ids the bundle does
   * not include. */
  public Effect<User> restore(User state) {
    return effects().updateState(state).thenReply(state);
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

  /** ldapsync's reconcile key: the LDAP entry's own unique-identifier attribute, so a later
   * sync recognizes this user again by {@code ldapId} rather than creating a duplicate. */
  public Effect<User> createFromLdap(CreateFromLdap cmd) {
    if (currentState().id() != null) {
      return effects().error("User already exists");
    }
    var user = new User(
        cmd.id(), cmd.username(), cmd.email(), false, cmd.firstName(), cmd.lastName(),
        null, false, null, false, cmd.ldapId(), List.of(), cmd.nowMillis(), cmd.nowMillis());
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
