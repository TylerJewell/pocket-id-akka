package io.akka.pocketid.api;

import akka.http.javadsl.model.HttpResponse;
import akka.http.javadsl.model.StatusCodes;
import akka.javasdk.annotations.Acl;
import akka.javasdk.annotations.http.Get;
import akka.javasdk.annotations.http.HttpEndpoint;
import akka.javasdk.annotations.http.Put;
import akka.javasdk.client.ComponentClient;
import akka.javasdk.http.AbstractHttpEndpoint;
import akka.javasdk.http.HttpResponses;
import io.akka.pocketid.application.CustomClaimSetEntity;
import io.akka.pocketid.domain.CustomClaim;
import java.util.List;
import java.util.Set;

/** custom_claim_controller.go — per-user and per-group custom claim sets. Reserved OIDC claim
 * keys are rejected, matching custom_claim_service.go's validation. */
@Acl(allow = @Acl.Matcher(principal = Acl.Principal.ALL))
@HttpEndpoint("/api")
public class CustomClaimEndpoint extends AbstractHttpEndpoint {

  private static final Set<String> RESERVED = Set.of(
      "sub", "iss", "aud", "exp", "iat", "nonce", "auth_time", "acr", "amr", "azp",
      "name", "given_name", "family_name", "display_name", "preferred_username", "email", "email_verified", "groups");

  private final ComponentClient cc;

  public CustomClaimEndpoint(ComponentClient cc) { this.cc = cc; }

  private HttpResponse requireAdmin() {
    var u = AuthSupport.authenticatedUser(requestContext(), cc);
    if (u == null) return HttpResponses.ok(java.util.Map.of("error", "unauthorized")).withStatus(StatusCodes.UNAUTHORIZED);
    if (!u.isAdmin()) return HttpResponses.ok(java.util.Map.of("error", "forbidden")).withStatus(StatusCodes.FORBIDDEN);
    return null;
  }

  @Get("/custom-claims/suggestions")
  public HttpResponse suggestions() {
    var forbidden = requireAdmin();
    if (forbidden != null) return forbidden;
    return HttpResponses.ok(List.of("department", "employee_id", "cost_center", "title"));
  }

  private HttpResponse validate(List<CustomClaim> claims) {
    Set<String> seen = new java.util.HashSet<>();
    for (var c : claims) {
      if (RESERVED.contains(c.key())) {
        return HttpResponses.ok(java.util.Map.of("error", "'" + c.key() + "' is a reserved claim key")).withStatus(StatusCodes.BAD_REQUEST);
      }
      if (!seen.add(c.key())) {
        return HttpResponses.ok(java.util.Map.of("error", "duplicate claim key '" + c.key() + "'")).withStatus(StatusCodes.BAD_REQUEST);
      }
    }
    return null;
  }

  @Put("/custom-claims/user/{userId}")
  public HttpResponse setForUser(String userId, List<CustomClaim> claims) {
    var forbidden = requireAdmin();
    if (forbidden != null) return forbidden;
    var invalid = validate(claims);
    if (invalid != null) return invalid;
    var updated = cc.forKeyValueEntity(userId).method(CustomClaimSetEntity::set).invoke(new CustomClaimSetEntity.Set(claims));
    return HttpResponses.ok(updated);
  }

  @Put("/custom-claims/user-group/{userGroupId}")
  public HttpResponse setForGroup(String userGroupId, List<CustomClaim> claims) {
    var forbidden = requireAdmin();
    if (forbidden != null) return forbidden;
    var invalid = validate(claims);
    if (invalid != null) return invalid;
    var updated = cc.forKeyValueEntity(userGroupId).method(CustomClaimSetEntity::set).invoke(new CustomClaimSetEntity.Set(claims));
    return HttpResponses.ok(updated);
  }
}
