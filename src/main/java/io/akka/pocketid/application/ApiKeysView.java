package io.akka.pocketid.application;

import akka.javasdk.annotations.Component;
import akka.javasdk.annotations.Consume;
import akka.javasdk.annotations.Query;
import akka.javasdk.view.TableUpdater;
import akka.javasdk.view.View;
import io.akka.pocketid.domain.ApiKeyRecord;
import java.util.List;
import java.util.Optional;

@Component(id = "api-keys-view")
public class ApiKeysView extends View {

  public record Row(
      String id, String name, Optional<String> description, String hashedKey, String userId,
      long expiresAtMillis, Optional<Long> lastUsedAtMillis, long createdAtMillis) {

    static Row from(ApiKeyRecord k) {
      return new Row(k.id(), k.name(), Optional.ofNullable(k.description()), k.hashedKey(), k.userId(),
          k.expiresAtMillis(), Optional.ofNullable(k.lastUsedAtMillis()), k.createdAtMillis());
    }

    ApiKeyRecord toRecord() {
      return new ApiKeyRecord(id, name, description.orElse(null), hashedKey, userId, expiresAtMillis, lastUsedAtMillis.orElse(null), createdAtMillis);
    }
  }

  public record Keys(List<Row> items) {
    public List<ApiKeyRecord> keys() {
      return items.stream().map(Row::toRecord).toList();
    }
  }

  @Consume.FromKeyValueEntity(ApiKeyEntity.class)
  public static class Updater extends TableUpdater<Row> {
    public Effect<Row> onUpdate(ApiKeyRecord state) {
      if (state.id() == null) return effects().ignore();
      return effects().updateRow(Row.from(state));
    }
  }

  @Query("SELECT * AS items FROM api_keys_view WHERE userId = :userId")
  public QueryEffect<Keys> byUser(String userId) {
    return queryResult();
  }

  @Query("SELECT * AS items FROM api_keys_view")
  public QueryEffect<Keys> all() {
    return queryResult();
  }

  @Query("SELECT * AS items FROM api_keys_view WHERE hashedKey = :hashedKey")
  public QueryEffect<Keys> byHashedKey(String hashedKey) {
    return queryResult();
  }
}
