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
import io.akka.pocketid.application.BlobEntity;
import io.akka.pocketid.application.OidcClientEntity;
import io.akka.pocketid.application.OidcClientsView;
import io.akka.pocketid.domain.OidcClient;
import java.security.SecureRandom;
import java.time.Instant;
import java.util.Base64;
import java.util.List;
import java.util.Map;
import java.util.UUID;

/** oidc_controller.go's client-management half (the protocol half is {@link io.akka.pocketid.api.OidcEndpoint}). */
@Acl(allow = @Acl.Matcher(principal = Acl.Principal.ALL))
@HttpEndpoint("/api")
public class OidcClientAdminEndpoint extends AbstractHttpEndpoint {

  private final ComponentClient cc;
  private static final SecureRandom RANDOM = new SecureRandom();

  public OidcClientAdminEndpoint(ComponentClient cc) { this.cc = cc; }

  private HttpResponse requireAdmin() {
    var u = AuthSupport.authenticatedUser(requestContext(), cc);
    if (u == null) return HttpResponses.ok(Map.of("error", "unauthorized")).withStatus(StatusCodes.UNAUTHORIZED);
    if (!u.isAdmin()) return HttpResponses.ok(Map.of("error", "forbidden")).withStatus(StatusCodes.FORBIDDEN);
    return null;
  }

  private static final Map<String, java.util.Comparator<OidcClient>> CLIENT_SORT = Map.of(
      "name", java.util.Comparator.comparing(OidcClient::name, String.CASE_INSENSITIVE_ORDER));

  private static final Map<String, java.util.function.Function<OidcClient, String>> CLIENT_FILTERS = Map.of(
      "isGroupRestricted", c -> String.valueOf(c.isGroupRestricted()),
      "isPublic", c -> String.valueOf(c.isPublic()));

  private boolean clientMatches(OidcClient c, String search) {
    String needle = search.toLowerCase();
    return c.name().toLowerCase().contains(needle) || c.description().toLowerCase().contains(needle);
  }

  @Get("/oidc/clients")
  public HttpResponse list() {
    var forbidden = requireAdmin();
    if (forbidden != null) return forbidden;
    var clients = cc.forView().method(OidcClientsView::all).invoke().clients();
    var params = ListQueryParams.from(requestContext());
    return HttpResponses.ok(params.apply(clients, c -> clientMatches(c, params.search), CLIENT_SORT, CLIENT_FILTERS));
  }

  /** RENDERING.md R1 — the client-list screen subscribes to this instead of polling. */
  @Get("/oidc/clients/stream")
  public HttpResponse stream() {
    var forbidden = requireAdmin();
    if (forbidden != null) return forbidden;
    var params = ListQueryParams.from(requestContext());
    return SseSupport.stream(() -> {
      var clients = cc.forView().method(OidcClientsView::all).invoke().clients();
      return params.apply(clients, c -> clientMatches(c, params.search), CLIENT_SORT, CLIENT_FILTERS);
    });
  }

  @Get("/oidc/clients/{id}")
  public HttpResponse get(String id) {
    var forbidden = requireAdmin();
    if (forbidden != null) return forbidden;
    var c = cc.forKeyValueEntity(id).method(OidcClientEntity::get).invoke();
    if (c.clientId() == null) return HttpResponses.ok(Map.of("error", "not found")).withStatus(StatusCodes.NOT_FOUND);
    return HttpResponses.ok(c);
  }

  @Get("/oidc/clients/{id}/meta")
  public HttpResponse meta(String id) {
    var c = cc.forKeyValueEntity(id).method(OidcClientEntity::get).invoke();
    if (c.clientId() == null) return HttpResponses.ok(Map.of("error", "not found")).withStatus(StatusCodes.NOT_FOUND);
    return HttpResponses.ok(Map.of("id", c.clientId(), "name", c.name(), "hasLogo", c.logoDataUrl() != null));
  }

  public record CreateClientRequest(String name, String description, boolean isPublic, List<String> redirectUris, List<String> postLogoutRedirectUris) {}

  @Post("/oidc/clients")
  public HttpResponse create(CreateClientRequest body) {
    var forbidden = requireAdmin();
    if (forbidden != null) return forbidden;
    String id = UUID.randomUUID().toString();
    String secret = body.isPublic() ? null : randomSecret();
    long now = Instant.now().toEpochMilli();
    var client = cc.forKeyValueEntity(id).method(OidcClientEntity::create).invoke(new OidcClientEntity.Create(
        id, body.name(), body.description(), secret, body.isPublic(),
        body.redirectUris() == null ? List.of() : body.redirectUris(),
        body.postLogoutRedirectUris() == null ? List.of() : body.postLogoutRedirectUris(), now));
    return HttpResponses.ok(clientWithSecret(client, secret)).withStatus(StatusCodes.CREATED);
  }

  private Map<String, Object> clientWithSecret(OidcClient c, String plaintextSecret) {
    var m = new java.util.LinkedHashMap<String, Object>();
    m.put("id", c.clientId());
    m.put("name", c.name());
    m.put("description", c.description());
    m.put("isPublic", c.isPublic());
    m.put("redirectUris", c.redirectUris());
    m.put("postLogoutRedirectUris", c.postLogoutRedirectUris());
    m.put("isGroupRestricted", c.isGroupRestricted());
    m.put("allowedUserGroupIds", c.allowedUserGroupIds());
    if (plaintextSecret != null) m.put("secret", plaintextSecret);
    return m;
  }

  private String randomSecret() {
    byte[] b = new byte[32];
    RANDOM.nextBytes(b);
    return Base64.getUrlEncoder().withoutPadding().encodeToString(b);
  }

  @Put("/oidc/clients/{id}")
  public HttpResponse update(String id, CreateClientRequest body) {
    var forbidden = requireAdmin();
    if (forbidden != null) return forbidden;
    var updated = cc.forKeyValueEntity(id).method(OidcClientEntity::update).invoke(new OidcClientEntity.Update(
        body.name(), body.description(), body.isPublic(),
        body.redirectUris() == null ? List.of() : body.redirectUris(),
        body.postLogoutRedirectUris() == null ? List.of() : body.postLogoutRedirectUris(), Instant.now().toEpochMilli()));
    return HttpResponses.ok(updated);
  }

  @Delete("/oidc/clients/{id}")
  public HttpResponse delete(String id) {
    var forbidden = requireAdmin();
    if (forbidden != null) return forbidden;
    cc.forKeyValueEntity(id).method(OidcClientEntity::delete).invoke();
    return HttpResponses.ok(Map.of("status", "deleted"));
  }

  @Post("/oidc/clients/{id}/refresh")
  public HttpResponse refreshSecret(String id) {
    var forbidden = requireAdmin();
    if (forbidden != null) return forbidden;
    String secret = randomSecret();
    var updated = cc.forKeyValueEntity(id).method(OidcClientEntity::refreshSecret)
        .invoke(new OidcClientEntity.RefreshSecret(secret, Instant.now().toEpochMilli()));
    return HttpResponses.ok(clientWithSecret(updated, secret));
  }

  public record SetAllowedGroupsRequest(boolean isGroupRestricted, List<String> userGroupIds) {}

  @Put("/oidc/clients/{id}/allowed-user-groups")
  public HttpResponse setAllowedGroups(String id, SetAllowedGroupsRequest body) {
    var forbidden = requireAdmin();
    if (forbidden != null) return forbidden;
    var updated = cc.forKeyValueEntity(id).method(OidcClientEntity::setAllowedUserGroups)
        .invoke(new OidcClientEntity.SetAllowedUserGroups(body.isGroupRestricted(), body.userGroupIds(), Instant.now().toEpochMilli()));
    return HttpResponses.ok(updated);
  }

  @Get("/oidc/clients/{id}/logo")
  public HttpResponse getLogo(String id) {
    var c = cc.forKeyValueEntity(id).method(OidcClientEntity::get).invoke();
    if (c.clientId() == null || c.logoDataUrl() == null) return HttpResponse.create().withStatus(StatusCodes.NOT_FOUND);
    var blob = cc.forKeyValueEntity("client-logo:" + id).method(BlobEntity::get).invoke();
    if (blob.isEmpty()) return HttpResponse.create().withStatus(StatusCodes.NOT_FOUND);
    byte[] bytes = Base64.getDecoder().decode(blob.base64Data());
    var ct = akka.http.javadsl.model.ContentTypes.parse(blob.contentType() == null ? "image/png" : blob.contentType());
    return HttpResponse.create().withEntity(ct, akka.util.ByteString.fromArray(bytes));
  }

  public record LogoUpload(String base64Data, String contentType) {}

  @Post("/oidc/clients/{id}/logo")
  public HttpResponse setLogo(String id, LogoUpload body) {
    var forbidden = requireAdmin();
    if (forbidden != null) return forbidden;
    cc.forKeyValueEntity("client-logo:" + id).method(BlobEntity::put).invoke(new BlobEntity.Put("client-logo:" + id, body.contentType(), body.base64Data()));
    var updated = cc.forKeyValueEntity(id).method(OidcClientEntity::setLogo).invoke(new OidcClientEntity.SetLogo("stored", Instant.now().toEpochMilli()));
    return HttpResponses.ok(updated);
  }

  @Delete("/oidc/clients/{id}/logo")
  public HttpResponse deleteLogo(String id) {
    var forbidden = requireAdmin();
    if (forbidden != null) return forbidden;
    cc.forKeyValueEntity("client-logo:" + id).method(BlobEntity::delete).invoke();
    var updated = cc.forKeyValueEntity(id).method(OidcClientEntity::setLogo).invoke(new OidcClientEntity.SetLogo(null, Instant.now().toEpochMilli()));
    return HttpResponses.ok(updated);
  }

  // ---- a user's own authorized-clients view ------------------------------------------------

  @Get("/oidc/users/me/clients")
  public HttpResponse myClients() {
    var u = AuthSupport.authenticatedUser(requestContext(), cc);
    if (u == null) return HttpResponses.ok(Map.of("error", "unauthorized")).withStatus(StatusCodes.UNAUTHORIZED);
    var clients = cc.forView().method(OidcClientsView::all).invoke().clients().stream()
        .filter(c -> c.userGroupAllowed(u.groupIds()))
        .toList();
    return HttpResponses.ok(Dtos.page(clients));
  }
}
