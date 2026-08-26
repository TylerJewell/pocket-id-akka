package io.akka.pocketid.api;

import akka.http.javadsl.model.HttpResponse;
import akka.http.javadsl.model.StatusCodes;
import akka.javasdk.annotations.Acl;
import akka.javasdk.annotations.http.Delete;
import akka.javasdk.annotations.http.HttpEndpoint;
import akka.javasdk.annotations.http.Post;
import akka.javasdk.annotations.http.Put;
import akka.javasdk.client.ComponentClient;
import akka.javasdk.http.AbstractHttpEndpoint;
import akka.javasdk.http.HttpResponses;
import io.akka.pocketid.application.ScimSync;
import io.akka.pocketid.application.ServiceProviderEntity;
import java.time.Instant;
import java.util.Map;
import java.util.UUID;

/** scimsync — SCIM 2.0 provisioning targets, one per OIDC client, and the sync trigger. */
@Acl(allow = @Acl.Matcher(principal = Acl.Principal.ALL))
@HttpEndpoint("/api/scim")
public class ServiceProviderEndpoint extends AbstractHttpEndpoint {

  private final ComponentClient cc;

  public ServiceProviderEndpoint(ComponentClient cc) { this.cc = cc; }

  private HttpResponse requireAdmin() {
    var u = AuthSupport.authenticatedUser(requestContext(), cc);
    if (u == null) return HttpResponses.ok(Map.of("error", "unauthorized")).withStatus(StatusCodes.UNAUTHORIZED);
    if (!u.isAdmin()) return HttpResponses.ok(Map.of("error", "forbidden")).withStatus(StatusCodes.FORBIDDEN);
    return null;
  }

  public record CreateProviderRequest(String oidcClientId, String endpointUrl, String bearerToken) {}

  @Post("/service-provider")
  public HttpResponse create(CreateProviderRequest body) {
    var forbidden = requireAdmin();
    if (forbidden != null) return forbidden;
    String id = UUID.randomUUID().toString();
    var sp = cc.forKeyValueEntity(id).method(ServiceProviderEntity::create)
        .invoke(new ServiceProviderEntity.Create(id, body.oidcClientId(), body.endpointUrl(), body.bearerToken(), Instant.now().toEpochMilli()));
    return HttpResponses.ok(sp).withStatus(StatusCodes.CREATED);
  }

  @Put("/service-provider/{id}")
  public HttpResponse update(String id, CreateProviderRequest body) {
    var forbidden = requireAdmin();
    if (forbidden != null) return forbidden;
    var sp = cc.forKeyValueEntity(id).method(ServiceProviderEntity::update).invoke(new ServiceProviderEntity.Update(body.endpointUrl(), body.bearerToken()));
    return HttpResponses.ok(sp);
  }

  @Delete("/service-provider/{id}")
  public HttpResponse delete(String id) {
    var forbidden = requireAdmin();
    if (forbidden != null) return forbidden;
    cc.forKeyValueEntity(id).method(ServiceProviderEntity::delete).invoke();
    return HttpResponses.ok(Map.of("status", "deleted"));
  }

  @Post("/service-provider/{id}/sync")
  public HttpResponse sync(String id) {
    var forbidden = requireAdmin();
    if (forbidden != null) return forbidden;
    var sp = cc.forKeyValueEntity(id).method(ServiceProviderEntity::get).invoke();
    if (sp.id() == null) return HttpResponses.ok(Map.of("error", "not found")).withStatus(StatusCodes.NOT_FOUND);
    var result = ScimSync.sync(sp, cc);
    cc.forKeyValueEntity(id).method(ServiceProviderEntity::markSynced).invoke(new ServiceProviderEntity.MarkSynced(Instant.now().toEpochMilli()));
    return HttpResponses.ok(Map.of("usersPushed", result.usersPushed(), "groupsPushed", result.groupsPushed(), "errors", result.errors()));
  }
}
