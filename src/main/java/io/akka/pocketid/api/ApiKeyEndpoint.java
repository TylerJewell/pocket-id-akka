package io.akka.pocketid.api;

import akka.http.javadsl.model.HttpResponse;
import akka.http.javadsl.model.StatusCodes;
import akka.javasdk.annotations.Acl;
import akka.javasdk.annotations.http.Delete;
import akka.javasdk.annotations.http.Get;
import akka.javasdk.annotations.http.HttpEndpoint;
import akka.javasdk.annotations.http.Post;
import akka.javasdk.client.ComponentClient;
import akka.javasdk.http.AbstractHttpEndpoint;
import akka.javasdk.http.HttpResponses;
import io.akka.pocketid.application.ApiKeyEntity;
import io.akka.pocketid.application.ApiKeysView;
import java.security.SecureRandom;
import java.time.Instant;
import java.util.Base64;
import java.util.UUID;

/** apikey — personal access tokens, session/JWT-authenticated only (matches the source: minting
 * a new key with an API key is not allowed, to bound how far one leaked key can escalate). */
@Acl(allow = @Acl.Matcher(principal = Acl.Principal.ALL))
@HttpEndpoint("/api")
public class ApiKeyEndpoint extends AbstractHttpEndpoint {

  private final ComponentClient cc;
  private static final SecureRandom RANDOM = new SecureRandom();

  public ApiKeyEndpoint(ComponentClient cc) { this.cc = cc; }

  private io.akka.pocketid.domain.User requireSession() {
    return AuthSupport.authenticatedUser(requestContext(), cc);
  }

  private static String randomKey() {
    byte[] b = new byte[32];
    RANDOM.nextBytes(b);
    return "pid_" + Base64.getUrlEncoder().withoutPadding().encodeToString(b);
  }

  private static final java.util.Map<String, java.util.Comparator<io.akka.pocketid.domain.ApiKeyRecord>> API_KEY_SORT =
      java.util.Map.of(
          "name", java.util.Comparator.comparing(io.akka.pocketid.domain.ApiKeyRecord::name, String.CASE_INSENSITIVE_ORDER),
          "expiresAt", java.util.Comparator.comparingLong(io.akka.pocketid.domain.ApiKeyRecord::expiresAtMillis),
          "lastUsedAt", java.util.Comparator.comparing(
              io.akka.pocketid.domain.ApiKeyRecord::lastUsedAtMillis,
              java.util.Comparator.nullsFirst(java.util.Comparator.naturalOrder())),
          "createdAt", java.util.Comparator.comparingLong(io.akka.pocketid.domain.ApiKeyRecord::createdAtMillis));

  private boolean apiKeyMatches(io.akka.pocketid.domain.ApiKeyRecord k, String search) {
    String needle = search.toLowerCase();
    return k.name().toLowerCase().contains(needle) || k.description().toLowerCase().contains(needle);
  }

  @Get("/api-keys")
  public HttpResponse list() {
    var u = requireSession();
    if (u == null) return HttpResponses.ok(java.util.Map.of("error", "unauthorized")).withStatus(StatusCodes.UNAUTHORIZED);
    var keys = cc.forView().method(ApiKeysView::byUser).invoke(u.id()).keys();
    var params = ListQueryParams.from(requestContext());
    return HttpResponses.ok(params.apply(keys, k -> apiKeyMatches(k, params.search), API_KEY_SORT));
  }

  /** RENDERING.md R1 — the api-key-list screen subscribes to this instead of polling. */
  @Get("/api-keys/stream")
  public HttpResponse stream() {
    var u = requireSession();
    if (u == null) return HttpResponses.ok(java.util.Map.of("error", "unauthorized")).withStatus(StatusCodes.UNAUTHORIZED);
    var params = ListQueryParams.from(requestContext());
    return SseSupport.stream(() -> {
      var keys = cc.forView().method(ApiKeysView::byUser).invoke(u.id()).keys();
      return params.apply(keys, k -> apiKeyMatches(k, params.search), API_KEY_SORT);
    });
  }

  public record CreateApiKeyRequest(String name, String description, long expiresAtMillis) {}

  @Post("/api-keys")
  public HttpResponse create(CreateApiKeyRequest body) {
    var u = requireSession();
    if (u == null) return HttpResponses.ok(java.util.Map.of("error", "unauthorized")).withStatus(StatusCodes.UNAUTHORIZED);
    long now = Instant.now().toEpochMilli();
    if (body.expiresAtMillis() <= now) {
      return HttpResponses.ok(java.util.Map.of("error", "expiresAt must be in the future")).withStatus(StatusCodes.BAD_REQUEST);
    }
    String id = UUID.randomUUID().toString();
    String raw = randomKey();
    cc.forKeyValueEntity(id).method(ApiKeyEntity::create)
        .invoke(new ApiKeyEntity.Create(id, body.name(), body.description(), AuthSupport.sha256(raw), u.id(), body.expiresAtMillis(), now));
    return HttpResponses.ok(java.util.Map.of("id", id, "apiKey", raw)).withStatus(StatusCodes.CREATED);
  }

  public record RenewApiKeyRequest(long expiresAtMillis) {}

  @Post("/api-keys/{id}/renew")
  public HttpResponse renew(String id, RenewApiKeyRequest body) {
    var u = requireSession();
    if (u == null) return HttpResponses.ok(java.util.Map.of("error", "unauthorized")).withStatus(StatusCodes.UNAUTHORIZED);
    var existing = cc.forKeyValueEntity(id).method(ApiKeyEntity::get).invoke();
    if (existing.id() == null) return HttpResponses.ok(java.util.Map.of("error", "not found")).withStatus(StatusCodes.NOT_FOUND);
    long now = Instant.now().toEpochMilli();
    if (existing.expiresAtMillis() > now) {
      return HttpResponses.ok(java.util.Map.of("error", "API key has not expired yet")).withStatus(StatusCodes.BAD_REQUEST);
    }
    String raw = randomKey();
    cc.forKeyValueEntity(id).method(ApiKeyEntity::renew).invoke(new ApiKeyEntity.Renew(body.expiresAtMillis(), AuthSupport.sha256(raw)));
    return HttpResponses.ok(java.util.Map.of("id", id, "apiKey", raw));
  }

  @Delete("/api-keys/{id}")
  public HttpResponse delete(String id) {
    var u = requireSession();
    if (u == null) return HttpResponses.ok(java.util.Map.of("error", "unauthorized")).withStatus(StatusCodes.UNAUTHORIZED);
    cc.forKeyValueEntity(id).method(ApiKeyEntity::delete).invoke();
    return HttpResponses.ok(java.util.Map.of("status", "deleted"));
  }
}
