package io.akka.pocketid.application;

import akka.javasdk.annotations.Component;
import akka.javasdk.annotations.Consume;
import akka.javasdk.annotations.Query;
import akka.javasdk.view.TableUpdater;
import akka.javasdk.view.View;
import java.util.List;
import java.util.Optional;

/** Resolves the short user code shown to a person into the device code entity holding the grant. */
@Component(id = "device-codes-view")
public class DeviceCodesView extends View {

  public record Row(String deviceCode, String userCode, String clientId, String scope,
      long expiresAtMillis, DeviceCodeEntity.Status status, Optional<String> subject, long intervalSeconds) {

    static Row from(DeviceCodeEntity.State s) {
      return new Row(s.deviceCode(), s.userCode(), s.clientId(), s.scope(), s.expiresAtMillis(), s.status(), Optional.ofNullable(s.subject()), s.intervalSeconds());
    }

    DeviceCodeEntity.State toState() {
      return new DeviceCodeEntity.State(deviceCode, userCode, clientId, scope, expiresAtMillis, status, subject.orElse(null), intervalSeconds);
    }
  }

  public record Codes(List<Row> items) {
    public List<DeviceCodeEntity.State> codes() {
      return items.stream().map(Row::toState).toList();
    }
  }

  @Consume.FromKeyValueEntity(DeviceCodeEntity.class)
  public static class Updater extends TableUpdater<Row> {
    public Effect<Row> onUpdate(DeviceCodeEntity.State state) {
      if (state.deviceCode() == null) return effects().ignore();
      return effects().updateRow(Row.from(state));
    }
  }

  @Query("SELECT * AS items FROM device_codes_view WHERE userCode = :userCode")
  public QueryEffect<Codes> byUserCode(String userCode) {
    return queryResult();
  }
}
