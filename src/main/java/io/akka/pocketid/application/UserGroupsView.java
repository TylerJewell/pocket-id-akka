package io.akka.pocketid.application;

import akka.javasdk.annotations.Component;
import akka.javasdk.annotations.Consume;
import akka.javasdk.annotations.Query;
import akka.javasdk.view.TableUpdater;
import akka.javasdk.view.View;
import io.akka.pocketid.domain.UserGroup;
import java.util.List;
import java.util.Optional;

@Component(id = "user-groups-view")
public class UserGroupsView extends View {

  public record Row(String id, String name, Optional<String> friendlyName, List<String> userIds,
      List<String> allowedOidcClientIds, long createdAtMillis, long updatedAtMillis) {

    static Row from(UserGroup g) {
      return new Row(g.id(), g.name(), Optional.ofNullable(g.friendlyName()), g.userIds(), g.allowedOidcClientIds(), g.createdAtMillis(), g.updatedAtMillis());
    }

    UserGroup toGroup() {
      return new UserGroup(id, name, friendlyName.orElse(null), userIds, allowedOidcClientIds, createdAtMillis, updatedAtMillis);
    }
  }

  public record Groups(List<Row> items) {
    public List<UserGroup> groups() {
      return items.stream().map(Row::toGroup).toList();
    }
  }

  @Consume.FromKeyValueEntity(UserGroupEntity.class)
  public static class Updater extends TableUpdater<Row> {
    public Effect<Row> onUpdate(UserGroup state) {
      if (state.id() == null) return effects().ignore();
      return effects().updateRow(Row.from(state));
    }
  }

  @Query("SELECT * AS items FROM user_groups_view")
  public QueryEffect<Groups> all() {
    return queryResult();
  }

  @Query("SELECT * AS items FROM user_groups_view WHERE name = :name")
  public QueryEffect<Groups> byName(String name) {
    return queryResult();
  }
}
