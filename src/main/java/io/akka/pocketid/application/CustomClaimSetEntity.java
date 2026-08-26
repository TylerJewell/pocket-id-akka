package io.akka.pocketid.application;

import akka.javasdk.annotations.Component;
import akka.javasdk.keyvalueentity.KeyValueEntity;
import io.akka.pocketid.domain.CustomClaim;
import java.util.List;

/** custom_claim_service.go — the set of custom claims attached to one user or one user group,
 * keyed by that owner's id (a user id and a group id never collide, both are UUIDs). */
@Component(id = "custom-claim-set")
public class CustomClaimSetEntity extends KeyValueEntity<CustomClaimSetEntity.State> {

  public record State(List<CustomClaim> claims) {}

  public record Set(List<CustomClaim> claims) {}

  @Override
  public State emptyState() {
    return new State(List.of());
  }

  public Effect<List<CustomClaim>> set(Set cmd) {
    return effects().updateState(new State(cmd.claims())).thenReply(cmd.claims());
  }

  public Effect<List<CustomClaim>> get() {
    return effects().reply(currentState().claims());
  }
}
