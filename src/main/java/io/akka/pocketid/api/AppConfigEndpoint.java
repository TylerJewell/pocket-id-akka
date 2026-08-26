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
import io.akka.pocketid.application.BlobEntity;
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

  @Get("/application-images/{name}")
  public HttpResponse getImage(String name) {
    if (!IMAGE_NAMES.contains(name)) return HttpResponse.create().withStatus(StatusCodes.NOT_FOUND);
    var blob = cc.forKeyValueEntity("app-image:" + name).method(BlobEntity::get).invoke();
    if (blob.isEmpty()) return HttpResponse.create().withStatus(StatusCodes.NOT_FOUND);
    byte[] bytes = java.util.Base64.getDecoder().decode(blob.base64Data());
    var ct = akka.http.javadsl.model.ContentTypes.parse(blob.contentType() == null ? "image/png" : blob.contentType());
    return HttpResponse.create().withEntity(ct, akka.util.ByteString.fromArray(bytes));
  }

  public record ImageUpload(String base64Data, String contentType) {}

  @Put("/application-images/{name}")
  public HttpResponse putImage(String name, ImageUpload body) {
    if (!IMAGE_NAMES.contains(name)) return HttpResponse.create().withStatus(StatusCodes.NOT_FOUND);
    if (!isAdmin()) return HttpResponses.ok(Map.of("error", "forbidden")).withStatus(StatusCodes.FORBIDDEN);
    cc.forKeyValueEntity("app-image:" + name).method(BlobEntity::put).invoke(new BlobEntity.Put("app-image:" + name, body.contentType(), body.base64Data()));
    return HttpResponses.ok(Map.of("status", "updated"));
  }

  @Delete("/application-images/{name}")
  public HttpResponse deleteImage(String name) {
    if (!IMAGE_NAMES.contains(name)) return HttpResponse.create().withStatus(StatusCodes.NOT_FOUND);
    if (!isAdmin()) return HttpResponses.ok(Map.of("error", "forbidden")).withStatus(StatusCodes.FORBIDDEN);
    cc.forKeyValueEntity("app-image:" + name).method(BlobEntity::delete).invoke();
    return HttpResponses.ok(Map.of("status", "deleted"));
  }
}
