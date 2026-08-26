package io.akka.pocketid.application;

import akka.javasdk.annotations.Component;
import akka.javasdk.annotations.Consume;
import akka.javasdk.annotations.Query;
import akka.javasdk.view.TableUpdater;
import akka.javasdk.view.View;
import io.akka.pocketid.domain.OidcClient;
import java.util.List;
import java.util.Optional;

@Component(id = "oidc-clients-view")
public class OidcClientsView extends View {

  public record Row(
      String clientId, String name, Optional<String> description, Optional<String> clientSecret, boolean isPublic,
      List<String> redirectUris, List<String> postLogoutRedirectUris, boolean isGroupRestricted,
      List<String> allowedUserGroupIds, Optional<String> logoDataUrl, long createdAtMillis, long updatedAtMillis) {

    static Row from(OidcClient c) {
      return new Row(c.clientId(), c.name(), Optional.ofNullable(c.description()), Optional.ofNullable(c.clientSecret()),
          c.isPublic(), c.redirectUris(), c.postLogoutRedirectUris(), c.isGroupRestricted(), c.allowedUserGroupIds(),
          Optional.ofNullable(c.logoDataUrl()), c.createdAtMillis(), c.updatedAtMillis());
    }

    OidcClient toClient() {
      return new OidcClient(clientId, name, description.orElse(null), clientSecret.orElse(null), isPublic, redirectUris,
          postLogoutRedirectUris, isGroupRestricted, allowedUserGroupIds, logoDataUrl.orElse(null), createdAtMillis, updatedAtMillis);
    }
  }

  public record Clients(List<Row> items) {
    public List<OidcClient> clients() {
      return items.stream().map(Row::toClient).toList();
    }
  }

  @Consume.FromKeyValueEntity(OidcClientEntity.class)
  public static class Updater extends TableUpdater<Row> {
    public Effect<Row> onUpdate(OidcClient state) {
      if (state.clientId() == null) return effects().ignore();
      return effects().updateRow(Row.from(state));
    }
  }

  @Query("SELECT * AS items FROM oidc_clients_view")
  public QueryEffect<Clients> all() {
    return queryResult();
  }
}
