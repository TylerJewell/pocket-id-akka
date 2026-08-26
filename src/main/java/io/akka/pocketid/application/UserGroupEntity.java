package io.akka.pocketid.application;

import akka.javasdk.annotations.Component;
import akka.javasdk.keyvalueentity.KeyValueEntity;
import io.akka.pocketid.domain.UserGroup;
import java.util.List;

/** A user group — user_group_service.go. Gates OIDC client access and fans out custom claims. */
@Component(id = "user-group")
public class UserGroupEntity extends KeyValueEntity<UserGroup> {

  public record Create(String id, String name, String friendlyName, long nowMillis) {}

  public record SetUsers(List<String> userIds, long nowMillis) {}

  public record SetAllowedClients(List<String> oidcClientIds, long nowMillis) {}

  public record Rename(String name, String friendlyName, long nowMillis) {}

  @Override
  public UserGroup emptyState() {
    return new UserGroup(null, null, null, List.of(), List.of(), 0, 0);
  }

  public Effect<UserGroup> create(Create cmd) {
    if (currentState().id() != null) return effects().error("Group already exists");
    var group = new UserGroup(cmd.id(), cmd.name(), cmd.friendlyName(), List.of(), List.of(), cmd.nowMillis(), cmd.nowMillis());
    return effects().updateState(group).thenReply(group);
  }

  public Effect<UserGroup> rename(Rename cmd) {
    if (currentState().id() == null) return effects().error("Group not found");
    var g = currentState();
    var updated = new UserGroup(g.id(), cmd.name(), cmd.friendlyName(), g.userIds(), g.allowedOidcClientIds(), g.createdAtMillis(), cmd.nowMillis());
    return effects().updateState(updated).thenReply(updated);
  }

  public Effect<UserGroup> setUsers(SetUsers cmd) {
    if (currentState().id() == null) return effects().error("Group not found");
    var g = currentState();
    var updated = new UserGroup(g.id(), g.name(), g.friendlyName(), cmd.userIds(), g.allowedOidcClientIds(), g.createdAtMillis(), cmd.nowMillis());
    return effects().updateState(updated).thenReply(updated);
  }

  public Effect<UserGroup> setAllowedClients(SetAllowedClients cmd) {
    if (currentState().id() == null) return effects().error("Group not found");
    var g = currentState();
    var updated = new UserGroup(g.id(), g.name(), g.friendlyName(), g.userIds(), cmd.oidcClientIds(), g.createdAtMillis(), cmd.nowMillis());
    return effects().updateState(updated).thenReply(updated);
  }

  public Effect<UserGroup> get() {
    return effects().reply(currentState());
  }

  public Effect<String> delete() {
    return effects().deleteEntity().thenReply("ok");
  }
}
