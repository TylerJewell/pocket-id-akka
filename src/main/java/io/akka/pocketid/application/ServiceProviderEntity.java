package io.akka.pocketid.application;

import akka.javasdk.annotations.Component;
import akka.javasdk.keyvalueentity.KeyValueEntity;
import io.akka.pocketid.domain.ServiceProvider;

/** scimsync — a SCIM 2.0 provisioning target for one OIDC client, keyed by its own id. */
@Component(id = "service-provider")
public class ServiceProviderEntity extends KeyValueEntity<ServiceProvider> {

  public record Create(String id, String oidcClientId, String endpointUrl, String bearerToken, long nowMillis) {}

  public record Update(String endpointUrl, String bearerToken) {}

  public record MarkSynced(long nowMillis) {}

  @Override
  public ServiceProvider emptyState() {
    return new ServiceProvider(null, null, null, null, null, 0);
  }

  public Effect<ServiceProvider> create(Create cmd) {
    var sp = new ServiceProvider(cmd.id(), cmd.oidcClientId(), cmd.endpointUrl(), cmd.bearerToken(), null, cmd.nowMillis());
    return effects().updateState(sp).thenReply(sp);
  }

  public Effect<ServiceProvider> update(Update cmd) {
    if (currentState().id() == null) return effects().error("Service provider not found");
    var s = currentState();
    var updated = new ServiceProvider(s.id(), s.oidcClientId(), cmd.endpointUrl(), cmd.bearerToken(), s.lastSyncedAtMillis(), s.createdAtMillis());
    return effects().updateState(updated).thenReply(updated);
  }

  public Effect<ServiceProvider> markSynced(MarkSynced cmd) {
    var s = currentState();
    var updated = new ServiceProvider(s.id(), s.oidcClientId(), s.endpointUrl(), s.bearerToken(), cmd.nowMillis(), s.createdAtMillis());
    return effects().updateState(updated).thenReply(updated);
  }

  public Effect<ServiceProvider> get() {
    return effects().reply(currentState());
  }

  public Effect<String> delete() {
    return effects().deleteEntity().thenReply("ok");
  }
}
