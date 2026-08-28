package io.akka.pocketid.application;

import akka.javasdk.annotations.Component;
import akka.javasdk.keyvalueentity.KeyValueEntity;
import io.akka.pocketid.domain.OidcClient;
import java.util.List;

/** A managed OAuth/OIDC client — oidc_controller.go, oidc/client_service.go. */
@Component(id = "oidc-client")
public class OidcClientEntity extends KeyValueEntity<OidcClient> {

  public record Create(
      String clientId, String name, String description, String clientSecret, boolean isPublic,
      List<String> redirectUris, List<String> postLogoutRedirectUris, long nowMillis) {}

  public record Update(
      String name, String description, boolean isPublic, List<String> redirectUris,
      List<String> postLogoutRedirectUris, long nowMillis) {}

  public record SetAllowedUserGroups(boolean isGroupRestricted, List<String> userGroupIds, long nowMillis) {}

  public record RefreshSecret(String newSecret, long nowMillis) {}

  public record SetLogo(String dataUrl, long nowMillis) {}

  @Override
  public OidcClient emptyState() {
    return new OidcClient(null, null, null, null, false, List.of(), List.of(), false, List.of(), null, 0, 0);
  }

  public Effect<OidcClient> create(Create cmd) {
    if (currentState().clientId() != null) return effects().error("Client already exists");
    var client = new OidcClient(
        cmd.clientId(), cmd.name(), cmd.description(), cmd.clientSecret(), cmd.isPublic(),
        cmd.redirectUris(), cmd.postLogoutRedirectUris(), false, List.of(), null, cmd.nowMillis(), cmd.nowMillis());
    return effects().updateState(client).thenReply(client);
  }

  public Effect<OidcClient> update(Update cmd) {
    if (currentState().clientId() == null) return effects().error("Client not found");
    var c = currentState();
    var updated = new OidcClient(
        c.clientId(), cmd.name(), cmd.description(), c.clientSecret(), cmd.isPublic(), cmd.redirectUris(),
        cmd.postLogoutRedirectUris(), c.isGroupRestricted(), c.allowedUserGroupIds(), c.logoDataUrl(), c.createdAtMillis(), cmd.nowMillis());
    return effects().updateState(updated).thenReply(updated);
  }

  public Effect<OidcClient> setAllowedUserGroups(SetAllowedUserGroups cmd) {
    if (currentState().clientId() == null) return effects().error("Client not found");
    var c = currentState();
    var updated = new OidcClient(
        c.clientId(), c.name(), c.description(), c.clientSecret(), c.isPublic(), c.redirectUris(),
        c.postLogoutRedirectUris(), cmd.isGroupRestricted(), cmd.userGroupIds(), c.logoDataUrl(), c.createdAtMillis(), cmd.nowMillis());
    return effects().updateState(updated).thenReply(updated);
  }

  public Effect<OidcClient> refreshSecret(RefreshSecret cmd) {
    if (currentState().clientId() == null) return effects().error("Client not found");
    var c = currentState();
    var updated = new OidcClient(
        c.clientId(), c.name(), c.description(), cmd.newSecret(), c.isPublic(), c.redirectUris(),
        c.postLogoutRedirectUris(), c.isGroupRestricted(), c.allowedUserGroupIds(), c.logoDataUrl(), c.createdAtMillis(), cmd.nowMillis());
    return effects().updateState(updated).thenReply(updated);
  }

  public Effect<OidcClient> setLogo(SetLogo cmd) {
    if (currentState().clientId() == null) return effects().error("Client not found");
    var c = currentState();
    var updated = new OidcClient(
        c.clientId(), c.name(), c.description(), c.clientSecret(), c.isPublic(), c.redirectUris(),
        c.postLogoutRedirectUris(), c.isGroupRestricted(), c.allowedUserGroupIds(), cmd.dataUrl(), c.createdAtMillis(), cmd.nowMillis());
    return effects().updateState(updated).thenReply(updated);
  }

  public Effect<OidcClient> get() {
    return effects().reply(currentState());
  }

  public Effect<String> delete() {
    return effects().deleteEntity().thenReply("ok");
  }
}
