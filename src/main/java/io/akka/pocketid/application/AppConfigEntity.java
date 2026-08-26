package io.akka.pocketid.application;

import akka.javasdk.annotations.Component;
import akka.javasdk.keyvalueentity.KeyValueEntity;
import java.util.HashMap;
import java.util.Map;

/**
 * appconfig/model.go's {@code AppConfigModel} — a singleton entity (always addressed by id
 * "singleton") holding every runtime-configurable setting as a string, exactly as the source
 * stores it (typed only at the point of use, via {@code AppConfigValue.IsTrue()} etc).
 */
@Component(id = "app-config")
public class AppConfigEntity extends KeyValueEntity<AppConfigEntity.State> {

  public record State(Map<String, String> values) {}

  public record Update(Map<String, String> changes) {}

  @Override
  public State emptyState() {
    return new State(AppConfigDefaults.defaults());
  }

  /** Empty string resets a key to its default — appconfig/model.go's Replace/Update semantics. */
  public Effect<Map<String, String>> update(Update cmd) {
    var current = currentState().values();
    var merged = new HashMap<>(current.isEmpty() ? AppConfigDefaults.defaults() : current);
    var defaults = AppConfigDefaults.defaults();
    for (var e : cmd.changes().entrySet()) {
      if (!defaults.containsKey(e.getKey())) {
        return effects().error("Unknown application configuration key: " + e.getKey());
      }
      merged.put(e.getKey(), e.getValue() == null || e.getValue().isEmpty() ? defaults.get(e.getKey()) : e.getValue());
    }
    return effects().updateState(new State(merged)).thenReply(merged);
  }

  public Effect<Map<String, String>> get() {
    var values = currentState().values();
    return effects().reply(values.isEmpty() ? AppConfigDefaults.defaults() : values);
  }
}
