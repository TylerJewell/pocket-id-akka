package io.akka.pocketid.application;

import akka.javasdk.annotations.Component;
import akka.javasdk.keyvalueentity.KeyValueEntity;
import io.akka.pocketid.domain.ApiKeyRecord;

/** apikey/models.go — a personal access token. Keyed by the SHA-256 hash of the raw key, so
 * lookup-by-presented-key is a direct entity read rather than a scan. */
@Component(id = "api-key")
public class ApiKeyEntity extends KeyValueEntity<ApiKeyRecord> {

  public record Create(String id, String name, String description, String hashedKey, String userId, long expiresAtMillis, long nowMillis) {}

  public record Renew(long newExpiresAtMillis, String newHashedKey) {}

  public record Touch(long nowMillis) {}

  @Override
  public ApiKeyRecord emptyState() {
    return new ApiKeyRecord(null, null, null, null, null, 0, null, 0);
  }

  public Effect<ApiKeyRecord> create(Create cmd) {
    var rec = new ApiKeyRecord(cmd.id(), cmd.name(), cmd.description(), cmd.hashedKey(), cmd.userId(), cmd.expiresAtMillis(), null, cmd.nowMillis());
    return effects().updateState(rec).thenReply(rec);
  }

  public Effect<ApiKeyRecord> renew(Renew cmd) {
    if (currentState().id() == null) return effects().error("Key not found");
    var k = currentState();
    var updated = new ApiKeyRecord(k.id(), k.name(), k.description(), cmd.newHashedKey(), k.userId(), cmd.newExpiresAtMillis(), k.lastUsedAtMillis(), k.createdAtMillis());
    return effects().updateState(updated).thenReply(updated);
  }

  public Effect<ApiKeyRecord> touch(Touch cmd) {
    if (currentState().id() == null) return effects().error("Key not found");
    var k = currentState();
    var updated = new ApiKeyRecord(k.id(), k.name(), k.description(), k.hashedKey(), k.userId(), k.expiresAtMillis(), cmd.nowMillis(), k.createdAtMillis());
    return effects().updateState(updated).thenReply(updated);
  }

  public Effect<ApiKeyRecord> get() {
    return effects().reply(currentState());
  }

  /** Backup-restore's equivalent for one API key record — see {@link UserEntity#restore}. */
  public Effect<ApiKeyRecord> restore(ApiKeyRecord state) {
    return effects().updateState(state).thenReply(state);
  }

  public Effect<String> delete() {
    return effects().deleteEntity().thenReply("ok");
  }
}
