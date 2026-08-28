package io.akka.pocketid.application;

import akka.javasdk.annotations.Component;
import akka.javasdk.keyvalueentity.KeyValueEntity;

/**
 * Caches a fetched Client ID Metadata Document by its URL (which is also the OIDC
 * {@code client_id}) — `cimd.go`'s resolver cache. A normal {@code /authorize}/{@code /token}
 * request reuses whatever is cached; {@code POST /api/oidc/clients/{id}/refresh} bypasses the
 * cache and re-fetches (`RefreshMetadataClient`).
 */
@Component(id = "cimd-cache")
public class CimdCacheEntity extends KeyValueEntity<CimdCacheEntity.State> {

  public record State(String url, String rawJson, long fetchedAtMillis) {
    public boolean isEmpty() { return url == null; }
  }

  public record Put(String url, String rawJson, long fetchedAtMillis) {}

  @Override
  public State emptyState() {
    return new State(null, null, 0);
  }

  public Effect<State> put(Put cmd) {
    var s = new State(cmd.url(), cmd.rawJson(), cmd.fetchedAtMillis());
    return effects().updateState(s).thenReply(s);
  }

  public Effect<State> get() {
    return effects().reply(currentState());
  }
}
