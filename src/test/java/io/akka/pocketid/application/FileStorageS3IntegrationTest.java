package io.akka.pocketid.application;

import static org.assertj.core.api.Assertions.assertThat;

import java.util.Base64;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.condition.EnabledIfEnvironmentVariable;

/**
 * `storage/s3.go`'s S3 backend, exercised against a real S3-compatible endpoint — not mocked,
 * per PIPELINE.md's "prefer running it" rule. Skipped unless {@code S3_BUCKET} is set, since a
 * real bucket is required; verified during this port's session against a local MinIO container
 * (docker run minio/minio, {@code S3_ENDPOINT=http://localhost:<port>},
 * {@code S3_FORCE_PATH_STYLE=true}), which is exactly the "S3-compatible non-AWS backend" case
 * {@link FileStorage}'s env knobs exist for. This test does not start that container itself —
 * CLAUDE.md's docker-daemon rule reserves container lifecycle management for the port session,
 * not the ordinary `mvn verify` run every other test in this suite goes through.
 */
public class FileStorageS3IntegrationTest {

  @Test
  @EnabledIfEnvironmentVariable(named = "S3_BUCKET", matches = ".+")
  void putGetAndDeleteRoundTripAgainstARealS3CompatibleEndpoint() {
    String id = "filestorage-s3-test-" + System.currentTimeMillis();
    String data = Base64.getEncoder().encodeToString("round trip".getBytes());

    FileStorage.put(null, id, "text/plain", data);
    var got = FileStorage.get(null, id);
    assertThat(got.isEmpty()).isFalse();
    assertThat(new String(Base64.getDecoder().decode(got.base64Data()))).isEqualTo("round trip");
    assertThat(got.contentType()).isEqualTo("text/plain");

    FileStorage.delete(null, id);
    assertThat(FileStorage.get(null, id).isEmpty()).isTrue();
  }
}
