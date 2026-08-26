package io.akka.pocketid.application;

import akka.javasdk.annotations.Component;
import akka.javasdk.keyvalueentity.KeyValueEntity;

/**
 * A generic named binary blob (base64-encoded), used for both user profile pictures
 * (app_images_service.go's per-user picture) and the app-wide images (favicon, logo, email
 * header, background, default profile picture) — storage.go's file-backed store, held here as
 * entity state rather than on a filesystem or in S3 (SPEC-001-pocket-id.md's B-1 scope note).
 */
@Component(id = "blob")
public class BlobEntity extends KeyValueEntity<BlobEntity.State> {

  public record State(String id, String contentType, String base64Data) {
    public boolean isEmpty() { return id == null; }
  }

  public record Put(String id, String contentType, String base64Data) {}

  @Override
  public State emptyState() {
    return new State(null, null, null);
  }

  public Effect<State> put(Put cmd) {
    var s = new State(cmd.id(), cmd.contentType(), cmd.base64Data());
    return effects().updateState(s).thenReply(s);
  }

  public Effect<State> get() {
    return effects().reply(currentState());
  }

  public Effect<String> delete() {
    return effects().deleteEntity().thenReply("ok");
  }
}
