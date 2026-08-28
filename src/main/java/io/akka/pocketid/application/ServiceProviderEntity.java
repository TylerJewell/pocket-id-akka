package io.akka.pocketid.application;

import akka.javasdk.annotations.Component;
import akka.javasdk.keyvalueentity.KeyValueEntity;
import io.akka.pocketid.domain.ServiceProvider;

/**
 * scimsync — a SCIM 2.0 provisioning target for one OIDC client, keyed by its own id.
 *
 * <p>{@code bearerToken} is stored encrypted at rest (AES-256-GCM, {@link EncryptionSupport}),
 * matching the source's {@code EncryptedString} treatment of {@code scimsync.ServiceProvider.
 * Token}. {@link #currentState()} therefore holds ciphertext; every command below decrypts
 * before replying so callers (the endpoint, {@link ScimSync}) always see plaintext.
 */
@Component(id = "service-provider")
public class ServiceProviderEntity extends KeyValueEntity<ServiceProvider> {

  public record Create(String id, String oidcClientId, String endpointUrl, String bearerToken, long nowMillis) {}

  public record Update(String endpointUrl, String bearerToken) {}

  public record MarkSynced(long nowMillis) {}

  public record Reencrypt(String oldMasterKey, String newMasterKey) {}

  @Override
  public ServiceProvider emptyState() {
    return new ServiceProvider(null, null, null, null, null, 0);
  }

  public Effect<ServiceProvider> create(Create cmd) {
    var encrypted = new ServiceProvider(cmd.id(), cmd.oidcClientId(), cmd.endpointUrl(),
        EncryptionSupport.encrypt(cmd.bearerToken(), EncryptionSupport.currentMasterKey()), null, cmd.nowMillis());
    var plain = new ServiceProvider(cmd.id(), cmd.oidcClientId(), cmd.endpointUrl(), cmd.bearerToken(), null, cmd.nowMillis());
    return effects().updateState(encrypted).thenReply(plain);
  }

  public Effect<ServiceProvider> update(Update cmd) {
    if (currentState().id() == null) return effects().error("Service provider not found");
    var s = currentState();
    var encrypted = new ServiceProvider(s.id(), s.oidcClientId(), cmd.endpointUrl(),
        EncryptionSupport.encrypt(cmd.bearerToken(), EncryptionSupport.currentMasterKey()), s.lastSyncedAtMillis(), s.createdAtMillis());
    var plain = new ServiceProvider(s.id(), s.oidcClientId(), cmd.endpointUrl(), cmd.bearerToken(), s.lastSyncedAtMillis(), s.createdAtMillis());
    return effects().updateState(encrypted).thenReply(plain);
  }

  public Effect<ServiceProvider> markSynced(MarkSynced cmd) {
    var s = currentState();
    var updated = new ServiceProvider(s.id(), s.oidcClientId(), s.endpointUrl(), s.bearerToken(), cmd.nowMillis(), s.createdAtMillis());
    return effects().updateState(updated).thenReply(decrypted(updated));
  }

  /** `encryption-key-rotate`'s SCIM-token half: re-wraps the already-persisted token under a new
   * master key without changing the token value itself. */
  public Effect<String> reencrypt(Reencrypt cmd) {
    if (currentState().id() == null) return effects().reply("ok");
    var s = currentState();
    var next = new ServiceProvider(s.id(), s.oidcClientId(), s.endpointUrl(),
        EncryptionSupport.reencrypt(s.bearerToken(), cmd.oldMasterKey(), cmd.newMasterKey()), s.lastSyncedAtMillis(), s.createdAtMillis());
    return effects().updateState(next).thenReply("ok");
  }

  public Effect<ServiceProvider> get() {
    return effects().reply(decrypted(currentState()));
  }

  public Effect<String> delete() {
    return effects().deleteEntity().thenReply("ok");
  }

  private static ServiceProvider decrypted(ServiceProvider encrypted) {
    if (encrypted.id() == null) return encrypted;
    return new ServiceProvider(encrypted.id(), encrypted.oidcClientId(), encrypted.endpointUrl(),
        EncryptionSupport.decrypt(encrypted.bearerToken(), EncryptionSupport.currentMasterKey()),
        encrypted.lastSyncedAtMillis(), encrypted.createdAtMillis());
  }
}
