package io.akka.pocketid.application;

import akka.javasdk.annotations.Component;
import akka.javasdk.keyvalueentity.KeyValueEntity;

/**
 * `import.go`'s {@code AcquireExclusive} — refuses a restore while another one is already in
 * progress. The source ties this to its Francis actor-cluster's own distributed lock (refusing
 * to run at all while any Pocket ID instance is connected); this port has no equivalent cluster
 * membership concept to gate on, so the guard here is narrower — one restore at a time within
 * this entity's own serialized command processing — which is a real, load-bearing narrowing
 * (multi-instance mutual exclusion is not provided) rather than a cosmetic rename, and is stated
 * as such in SPEC-001 §1 and the README's "Where it differs" list.
 */
@Component(id = "maintenance-lock")
public class MaintenanceLockEntity extends KeyValueEntity<MaintenanceLockEntity.State> {

  public record State(boolean held, long acquiredAtMillis) {}

  @Override
  public State emptyState() {
    return new State(false, 0);
  }

  public Effect<Boolean> tryAcquire(Long nowMillis) {
    if (currentState().held()) return effects().reply(false);
    return effects().updateState(new State(true, nowMillis)).thenReply(true);
  }

  public Effect<String> release() {
    return effects().updateState(new State(false, 0)).thenReply("ok");
  }
}
