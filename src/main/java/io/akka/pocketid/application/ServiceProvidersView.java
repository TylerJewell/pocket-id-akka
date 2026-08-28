package io.akka.pocketid.application;

import akka.javasdk.annotations.Component;
import akka.javasdk.annotations.Consume;
import akka.javasdk.annotations.Query;
import akka.javasdk.view.TableUpdater;
import akka.javasdk.view.View;
import io.akka.pocketid.domain.ServiceProvider;
import java.util.List;
import java.util.Optional;

@Component(id = "service-providers-view")
public class ServiceProvidersView extends View {

  public record Row(String id, String oidcClientId, String endpointUrl, String bearerToken,
      Optional<Long> lastSyncedAtMillis, long createdAtMillis) {

    /** {@code s.bearerToken()} is ciphertext here — {@link ServiceProviderEntity}'s persisted
     * state, pushed to this view straight from {@code updateState}, not the decrypted reply its
     * own commands hand back to a caller. */
    static Row from(ServiceProvider s) {
      String plainToken = EncryptionSupport.decrypt(s.bearerToken(), EncryptionSupport.currentMasterKey());
      return new Row(s.id(), s.oidcClientId(), s.endpointUrl(), plainToken, Optional.ofNullable(s.lastSyncedAtMillis()), s.createdAtMillis());
    }

    ServiceProvider toProvider() {
      return new ServiceProvider(id, oidcClientId, endpointUrl, bearerToken, lastSyncedAtMillis.orElse(null), createdAtMillis);
    }
  }

  public record Providers(List<Row> items) {
    public List<ServiceProvider> providers() {
      return items.stream().map(Row::toProvider).toList();
    }
  }

  @Consume.FromKeyValueEntity(ServiceProviderEntity.class)
  public static class Updater extends TableUpdater<Row> {
    public Effect<Row> onUpdate(ServiceProvider state) {
      if (state.id() == null) return effects().ignore();
      return effects().updateRow(Row.from(state));
    }
  }

  @Query("SELECT * AS items FROM service_providers_view")
  public QueryEffect<Providers> all() {
    return queryResult();
  }

  @Query("SELECT * AS items FROM service_providers_view WHERE oidcClientId = :oidcClientId")
  public QueryEffect<Providers> byClient(String oidcClientId) {
    return queryResult();
  }
}
