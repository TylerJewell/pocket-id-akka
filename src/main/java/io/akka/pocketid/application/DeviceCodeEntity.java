package io.akka.pocketid.application;

import akka.javasdk.annotations.Component;
import akka.javasdk.keyvalueentity.KeyValueEntity;

/**
 * RFC 8628 OAuth device authorization grant — one device/user code pair, keyed by the device
 * code. The user code is resolved to the device code through {@code DeviceCodesView} so the
 * verification screen (which only ever sees the short user code) can look it up.
 */
@Component(id = "device-code")
public class DeviceCodeEntity extends KeyValueEntity<DeviceCodeEntity.State> {

  public enum Status { PENDING, APPROVED, DENIED, CONSUMED }

  public record State(
      String deviceCode, String userCode, String clientId, String scope,
      long expiresAtMillis, Status status, String subject, long intervalSeconds) {
    public boolean isEmpty() { return deviceCode == null; }
  }

  public record Issue(String deviceCode, String userCode, String clientId, String scope, long expiresAtMillis, long intervalSeconds) {}

  public record Decide(boolean approve, String subject) {}

  @Override
  public State emptyState() {
    return new State(null, null, null, null, 0, Status.PENDING, null, 5);
  }

  public Effect<State> issue(Issue cmd) {
    var s = new State(cmd.deviceCode(), cmd.userCode(), cmd.clientId(), cmd.scope(), cmd.expiresAtMillis(), Status.PENDING, null, cmd.intervalSeconds());
    return effects().updateState(s).thenReply(s);
  }

  public Effect<State> decide(Decide cmd) {
    if (currentState().isEmpty()) return effects().error("Device code not found");
    var s = currentState();
    var updated = new State(s.deviceCode(), s.userCode(), s.clientId(), s.scope(), s.expiresAtMillis(),
        cmd.approve() ? Status.APPROVED : Status.DENIED, cmd.approve() ? cmd.subject() : null, s.intervalSeconds());
    return effects().updateState(updated).thenReply(updated);
  }

  public Effect<State> markConsumed() {
    var s = currentState();
    var updated = new State(s.deviceCode(), s.userCode(), s.clientId(), s.scope(), s.expiresAtMillis(), Status.CONSUMED, s.subject(), s.intervalSeconds());
    return effects().updateState(updated).thenReply(updated);
  }

  public Effect<State> get() {
    return effects().reply(currentState());
  }
}
