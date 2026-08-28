package io.akka.pocketid.application;

import akka.javasdk.client.ComponentClient;
import java.util.Base64;
import software.amazon.awssdk.auth.credentials.AwsBasicCredentials;
import software.amazon.awssdk.auth.credentials.StaticCredentialsProvider;
import software.amazon.awssdk.core.sync.RequestBody;
import software.amazon.awssdk.regions.Region;
import software.amazon.awssdk.services.s3.S3Client;
import software.amazon.awssdk.services.s3.model.DeleteObjectRequest;
import software.amazon.awssdk.services.s3.model.GetObjectRequest;
import software.amazon.awssdk.services.s3.model.NoSuchKeyException;
import software.amazon.awssdk.services.s3.model.PutObjectRequest;

/**
 * `storage.go`'s {@code FileStorage} interface — this port's default backend is the same shape
 * as the source's third option, {@code database} (`storage/database.go`): bytes held as entity
 * state ({@link BlobEntity}), which is what every blob consumer already used before this class
 * existed. Setting {@code S3_BUCKET} (plus region/endpoint/credentials) switches every one of
 * those same call sites to the source's {@code s3} backend instead, using the real AWS SDK
 * against any S3-compatible endpoint (MinIO included, via {@code S3_ENDPOINT} +
 * {@code S3_FORCE_PATH_STYLE} — the same two knobs the source's own S3 backend exposes for
 * non-AWS S3-compatible services).
 */
public final class FileStorage {
  private FileStorage() {}

  public record Blob(String contentType, String base64Data, boolean deleted) {
    public boolean isEmpty() { return (contentType == null && base64Data == null) || deleted; }
  }

  private static boolean s3Enabled() {
    String bucket = System.getenv("S3_BUCKET");
    return bucket != null && !bucket.isBlank();
  }

  private static S3Client s3Client() {
    var builder = S3Client.builder()
        .region(Region.of(envOr("S3_REGION", "us-east-1")))
        .forcePathStyle(Boolean.parseBoolean(envOr("S3_FORCE_PATH_STYLE", "false")));
    String endpoint = System.getenv("S3_ENDPOINT");
    if (endpoint != null && !endpoint.isBlank()) builder = builder.endpointOverride(java.net.URI.create(endpoint));
    String accessKeyId = System.getenv("S3_ACCESS_KEY_ID");
    String secretKey = System.getenv("S3_SECRET_ACCESS_KEY");
    if (accessKeyId != null && secretKey != null) {
      builder = builder.credentialsProvider(StaticCredentialsProvider.create(AwsBasicCredentials.create(accessKeyId, secretKey)));
    }
    return builder.build();
  }

  private static String envOr(String key, String fallback) {
    String v = System.getenv(key);
    return v == null || v.isBlank() ? fallback : v;
  }

  public static Blob get(ComponentClient cc, String id) {
    if (s3Enabled()) {
      try (S3Client s3 = s3Client()) {
        String bucket = System.getenv("S3_BUCKET");
        var meta = s3.headObject(b -> b.bucket(bucket).key(id));
        byte[] bytes = s3.getObject(GetObjectRequest.builder().bucket(bucket).key(id).build()).readAllBytes();
        return new Blob(meta.contentType(), Base64.getEncoder().encodeToString(bytes), false);
      } catch (NoSuchKeyException e) {
        return new Blob(null, null, false);
      } catch (java.io.IOException e) {
        throw new IllegalStateException("failed reading blob " + id + " from S3", e);
      }
    }
    var state = cc.forKeyValueEntity(id).method(BlobEntity::get).invoke();
    return new Blob(state.contentType(), state.base64Data(), state.deleted());
  }

  public static void put(ComponentClient cc, String id, String contentType, String base64Data) {
    if (s3Enabled()) {
      try (S3Client s3 = s3Client()) {
        byte[] bytes = Base64.getDecoder().decode(base64Data);
        s3.putObject(PutObjectRequest.builder().bucket(System.getenv("S3_BUCKET")).key(id).contentType(contentType).build(),
            RequestBody.fromBytes(bytes));
      }
      return;
    }
    cc.forKeyValueEntity(id).method(BlobEntity::put).invoke(new BlobEntity.Put(id, contentType, base64Data));
  }

  public static void delete(ComponentClient cc, String id) {
    if (s3Enabled()) {
      try (S3Client s3 = s3Client()) {
        s3.deleteObject(DeleteObjectRequest.builder().bucket(System.getenv("S3_BUCKET")).key(id).build());
      }
      return;
    }
    cc.forKeyValueEntity(id).method(BlobEntity::delete).invoke();
  }
}
