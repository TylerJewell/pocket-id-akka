package io.akka.pocketid.application;

import akka.javasdk.annotations.Component;
import akka.javasdk.keyvalueentity.KeyValueEntity;

/**
 * devicelogin — "login with another device": one browser shows a short code, a second
 * (already-authenticated) browser approves or denies it. Distinct from {@link DeviceCodeEntity},
 * which is the OAuth RFC 8628 grant a *client application* drives; this is the source's own
 * browser-to-browser handoff, keyed by the user code shown on the requesting device.
 */
@Component(id = "device-login")
public class DeviceLoginEntity extends KeyValueEntity<DeviceLoginEntity.State> {

  public enum Status { PENDING, APPROVED, DENIED, CONSUMED }

  public record State(String code, long expiresAtMillis, Status status, String subject) {
    public boolean isEmpty() { return code == null; }
  }

  public record Create(String code, long expiresAtMillis) {}

  public record Decide(boolean approve, String subject) {}

  @Override
  public State emptyState() {
    return new State(null, 0, Status.PENDING, null);
  }

  public Effect<State> create(Create cmd) {
    var s = new State(cmd.code(), cmd.expiresAtMillis(), Status.PENDING, null);
    return effects().updateState(s).thenReply(s);
  }

  public Effect<State> decide(Decide cmd) {
    if (currentState().isEmpty()) return effects().error("Request not found");
    var s = currentState();
    var updated = new State(s.code(), s.expiresAtMillis(), cmd.approve() ? Status.APPROVED : Status.DENIED, cmd.approve() ? cmd.subject() : null);
    return effects().updateState(updated).thenReply(updated);
  }

  public Effect<State> consume() {
    var s = currentState();
    var updated = new State(s.code(), s.expiresAtMillis(), Status.CONSUMED, s.subject());
    return effects().updateState(updated).thenReply(updated);
  }

  public Effect<State> get() {
    return effects().reply(currentState());
  }
}
