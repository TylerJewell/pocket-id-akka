package io.akka.pocketid.api;

import akka.http.javadsl.model.HttpResponse;
import akka.http.javadsl.model.StatusCodes;
import akka.javasdk.annotations.Acl;
import akka.javasdk.annotations.http.Delete;
import akka.javasdk.annotations.http.Get;
import akka.javasdk.annotations.http.HttpEndpoint;
import akka.javasdk.annotations.http.Post;
import akka.javasdk.annotations.http.Put;
import akka.javasdk.client.ComponentClient;
import akka.javasdk.http.AbstractHttpEndpoint;
import akka.javasdk.http.HttpResponses;
import io.akka.pocketid.application.AppConfigDefaults;
import io.akka.pocketid.application.AppConfigEntity;
import java.util.HashMap;
import java.util.Map;

/** app_config_controller.go + app_images_controller.go — runtime settings and the app-wide
 * uploaded images. GET is public but filtered to the {@code public:"true"} keys unless the
 * caller is an admin, matching the source's UI-config-disclosure rule. */
@Acl(allow = @Acl.Matcher(principal = Acl.Principal.ALL))
@HttpEndpoint("/api")
public class AppConfigEndpoint extends AbstractHttpEndpoint {

  private final ComponentClient cc;

  public AppConfigEndpoint(ComponentClient cc) { this.cc = cc; }

  private boolean isAdmin() {
    var u = AuthSupport.authenticatedUser(requestContext(), cc);
    return u != null && u.isAdmin();
  }

  @Get("/application-configuration")
  public HttpResponse getPublic() {
    var all = cc.forKeyValueEntity("singleton").method(AppConfigEntity::get).invoke();
    boolean admin = isAdmin();
    Map<String, String> out = new HashMap<>();
    for (var e : all.entrySet()) {
      if (admin || AppConfigDefaults.PUBLIC_KEYS.contains(e.getKey())) {
        out.put(e.getKey(), AppConfigDefaults.SENSITIVE_KEYS.contains(e.getKey()) && !admin ? "" : e.getValue());
      }
    }
    return HttpResponses.ok(out);
  }

  @Get("/application-configuration/all")
  public HttpResponse getAll() {
    if (!isAdmin()) return HttpResponses.ok(Map.of("error", "forbidden")).withStatus(StatusCodes.FORBIDDEN);
    return HttpResponses.ok(cc.forKeyValueEntity("singleton").method(AppConfigEntity::get).invoke());
  }

  /** The frontend's own contract is a flat JSON object of key/value settings
   * (app-config-service.ts); the SDK's HTTP body binding does not accept a bare {@code Map} as
   * a top-level request type, so this wraps it — the one place this port's data layer differs
   * from the source's request shape (RENDERING R3's "diff confined to the data layer"). */
  public record ConfigChanges(Map<String, String> values) {}

  @Put("/application-configuration")
  public HttpResponse update(ConfigChanges body) {
    if (!isAdmin()) return HttpResponses.ok(Map.of("error", "forbidden")).withStatus(StatusCodes.FORBIDDEN);
    var updated = cc.forKeyValueEntity("singleton").method(AppConfigEntity::update).invoke(new AppConfigEntity.Update(body.values()));
    return HttpResponses.ok(updated);
  }

  @Post("/application-configuration/test-email")
  public HttpResponse testEmail() {
    if (!isAdmin()) return HttpResponses.ok(Map.of("error", "forbidden")).withStatus(StatusCodes.FORBIDDEN);
    // Documented stub — SPEC scope note B-1: no SMTP fixture in this environment to check by running.
    return HttpResponses.ok(Map.of("status", "sent"));
  }

  /** `pocket-id key-rotate` — replaces the persisted JWT signing key. See
   * {@link io.akka.pocketid.application.SigningKeyEntity}'s class doc for why this is a real
   * rotation (persisted, survives a restart) rather than a per-process no-op. */
  @Post("/application-configuration/rotate-signing-key")
  public HttpResponse rotateSigningKey() {
    if (!isAdmin()) return HttpResponses.ok(Map.of("error", "forbidden")).withStatus(StatusCodes.FORBIDDEN);
    var next = io.akka.pocketid.application.SigningKeys.rotate(cc);
    return HttpResponses.ok(Map.of("keyId", next.keyId(), "rotatedAtMillis", next.rotatedAtMillis()));
  }

  @Post("/application-configuration/sync-ldap")
  public HttpResponse syncLdap() {
    if (!isAdmin()) return HttpResponses.ok(Map.of("error", "forbidden")).withStatus(StatusCodes.FORBIDDEN);
    var config = cc.forKeyValueEntity("singleton").method(AppConfigEntity::get).invoke();
    if (!Boolean.parseBoolean(config.getOrDefault("ldapEnabled", "false"))) {
      return HttpResponses.ok(Map.of("error", "LDAP is not enabled")).withStatus(StatusCodes.BAD_REQUEST);
    }
    var result = io.akka.pocketid.application.LdapSync.sync(config, cc);
    return HttpResponses.ok(Map.of("usersSynced", result.usersSynced(), "groupsSynced", result.groupsSynced()));
  }

  // ---- images (app-wide) -----------------------------------------------------------------

  private static final java.util.Set<String> IMAGE_NAMES = java.util.Set.of("favicon", "logo", "email", "background", "default-profile-picture");

  // backend/resources/images/ + app_images_bootstrap.go: the source copies these three bundled
  // files into its image store on first boot, so a fresh install serves them before any admin
  // ever uploads a replacement. Rather than a startup-time copy into a KeyValueEntity (no
  // lifecycle hook runs application code before the first request here), getImage falls back to
  // the bundled resource whenever nothing has been uploaded -- same visible result, checked by
  // running both sides side by side (gui/manifest.json's R4 appearance comparison surfaced the
  // 404 this fixes: the background pane was blank on the port and present on the source).
  private static final Map<String, String> DEFAULT_IMAGE_RESOURCES = Map.of(
      "background", "default-app-images/background.webp",
      "favicon", "default-app-images/favicon.ico",
      "email", "default-app-images/email.png");
  private static final Map<String, String> DEFAULT_IMAGE_CONTENT_TYPES = Map.of(
      "background", "image/webp",
      "favicon", "image/x-icon",
      "email", "image/png");

  @Get("/application-images/{name}")
  public HttpResponse getImage(String name) {
    if (!IMAGE_NAMES.contains(name)) return HttpResponse.create().withStatus(StatusCodes.NOT_FOUND);
    var blob = io.akka.pocketid.application.FileStorage.get(cc, "app-image:" + name);
    if (blob.isEmpty()) {
      // "never uploaded" gets the bundled default; "explicitly deleted" (BlobEntity's own
      // tombstone) does not -- matching the source's one deletable bundled image (the
      // background), which stays gone once removed rather than reappearing on next load.
      if (blob.deleted()) return HttpResponse.create().withStatus(StatusCodes.NOT_FOUND);
      var resourcePath = DEFAULT_IMAGE_RESOURCES.get(name);
      if (resourcePath == null) return HttpResponse.create().withStatus(StatusCodes.NOT_FOUND);
      try (var in = getClass().getClassLoader().getResourceAsStream(resourcePath)) {
        if (in == null) return HttpResponse.create().withStatus(StatusCodes.NOT_FOUND);
        byte[] bytes = in.readAllBytes();
        var ct = akka.http.javadsl.model.ContentTypes.parse(DEFAULT_IMAGE_CONTENT_TYPES.get(name));
        return HttpResponse.create().withEntity(ct, akka.util.ByteString.fromArray(bytes));
      } catch (java.io.IOException e) {
        return HttpResponse.create().withStatus(StatusCodes.NOT_FOUND);
      }
    }
    byte[] bytes = java.util.Base64.getDecoder().decode(blob.base64Data());
    var ct = akka.http.javadsl.model.ContentTypes.parse(blob.contentType() == null ? "image/png" : blob.contentType());
    return HttpResponse.create().withEntity(ct, akka.util.ByteString.fromArray(bytes));
  }

  public record ImageUpload(String base64Data, String contentType) {}

  @Put("/application-images/{name}")
  public HttpResponse putImage(String name, ImageUpload body) {
    if (!IMAGE_NAMES.contains(name)) return HttpResponse.create().withStatus(StatusCodes.NOT_FOUND);
    if (!isAdmin()) return HttpResponses.ok(Map.of("error", "forbidden")).withStatus(StatusCodes.FORBIDDEN);
    io.akka.pocketid.application.FileStorage.put(cc, "app-image:" + name, body.contentType(), body.base64Data());
    return HttpResponses.ok(Map.of("status", "updated"));
  }

  @Delete("/application-images/{name}")
  public HttpResponse deleteImage(String name) {
    if (!IMAGE_NAMES.contains(name)) return HttpResponse.create().withStatus(StatusCodes.NOT_FOUND);
    if (!isAdmin()) return HttpResponses.ok(Map.of("error", "forbidden")).withStatus(StatusCodes.FORBIDDEN);
    io.akka.pocketid.application.FileStorage.delete(cc, "app-image:" + name);
    return HttpResponses.ok(Map.of("status", "deleted"));
  }
}
