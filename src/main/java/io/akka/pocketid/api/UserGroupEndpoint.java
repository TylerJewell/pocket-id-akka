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
import io.akka.pocketid.application.CustomClaimSetEntity;
import io.akka.pocketid.application.UserGroupEntity;
import io.akka.pocketid.application.UserGroupsView;
import io.akka.pocketid.application.UsersView;
import io.akka.pocketid.domain.UserGroup;
import java.time.Instant;
import java.util.List;
import java.util.UUID;

/** user_group_controller.go — group CRUD, membership, allowed OIDC clients. */
@Acl(allow = @Acl.Matcher(principal = Acl.Principal.ALL))
@HttpEndpoint("/api")
public class UserGroupEndpoint extends AbstractHttpEndpoint {

  private final ComponentClient cc;

  public UserGroupEndpoint(ComponentClient cc) { this.cc = cc; }

  private HttpResponse requireAdmin() {
    var u = AuthSupport.authenticatedUser(requestContext(), cc);
    if (u == null) return HttpResponses.ok(java.util.Map.of("error", "unauthorized")).withStatus(StatusCodes.UNAUTHORIZED);
    if (!u.isAdmin()) return HttpResponses.ok(java.util.Map.of("error", "forbidden")).withStatus(StatusCodes.FORBIDDEN);
    return null;
  }

  private Dtos.UserGroupDto toDto(UserGroup g) {
    var users = cc.forView().method(UsersView::all).invoke().users().stream()
        .filter(u -> u.groupIds().contains(g.id()))
        .map(u -> new Dtos.UserMinimal(u.id(), u.username(), u.email(), u.firstName(), u.lastName()))
        .toList();
    var claims = cc.forKeyValueEntity(g.id()).method(CustomClaimSetEntity::get).invoke();
    return new Dtos.UserGroupDto(g.id(), g.name(), g.friendlyName(), users, claims);
  }

  private static final java.util.Map<String, java.util.Comparator<Dtos.UserGroupDto>> GROUP_SORT = java.util.Map.of(
      "friendlyName", java.util.Comparator.comparing(Dtos.UserGroupDto::friendlyName, String.CASE_INSENSITIVE_ORDER),
      "name", java.util.Comparator.comparing(Dtos.UserGroupDto::name, String.CASE_INSENSITIVE_ORDER),
      "userCount", java.util.Comparator.comparingInt(g -> g.users().size()));

  private boolean groupMatches(Dtos.UserGroupDto g, String search) {
    String needle = search.toLowerCase();
    return g.name().toLowerCase().contains(needle) || g.friendlyName().toLowerCase().contains(needle);
  }

  @Get("/user-groups")
  public HttpResponse list() {
    var forbidden = requireAdmin();
    if (forbidden != null) return forbidden;
    var groups = cc.forView().method(UserGroupsView::all).invoke().groups().stream().map(this::toDto).toList();
    var params = ListQueryParams.from(requestContext());
    return HttpResponses.ok(params.apply(groups, g -> groupMatches(g, params.search), GROUP_SORT));
  }

  /** RENDERING.md R1 — the group-list screen subscribes to this instead of polling. */
  @Get("/user-groups/stream")
  public HttpResponse stream() {
    var forbidden = requireAdmin();
    if (forbidden != null) return forbidden;
    var params = ListQueryParams.from(requestContext());
    return SseSupport.stream(() -> {
      var groups = cc.forView().method(UserGroupsView::all).invoke().groups().stream().map(this::toDto).toList();
      return params.apply(groups, g -> groupMatches(g, params.search), GROUP_SORT);
    });
  }

  @Get("/user-groups/{id}")
  public HttpResponse get(String id) {
    var forbidden = requireAdmin();
    if (forbidden != null) return forbidden;
    var g = cc.forKeyValueEntity(id).method(UserGroupEntity::get).invoke();
    if (g.id() == null) return HttpResponses.ok(java.util.Map.of("error", "not found")).withStatus(StatusCodes.NOT_FOUND);
    return HttpResponses.ok(toDto(g));
  }

  public record UpsertGroup(String name, String friendlyName) {}

  @Post("/user-groups")
  public HttpResponse create(UpsertGroup body) {
    var forbidden = requireAdmin();
    if (forbidden != null) return forbidden;
    String id = UUID.randomUUID().toString();
    var g = cc.forKeyValueEntity(id).method(UserGroupEntity::create)
        .invoke(new UserGroupEntity.Create(id, body.name(), body.friendlyName(), Instant.now().toEpochMilli()));
    return HttpResponses.ok(toDto(g)).withStatus(StatusCodes.CREATED);
  }

  @Put("/user-groups/{id}")
  public HttpResponse rename(String id, UpsertGroup body) {
    var forbidden = requireAdmin();
    if (forbidden != null) return forbidden;
    var g = cc.forKeyValueEntity(id).method(UserGroupEntity::rename)
        .invoke(new UserGroupEntity.Rename(body.name(), body.friendlyName(), Instant.now().toEpochMilli()));
    return HttpResponses.ok(toDto(g));
  }

  @Delete("/user-groups/{id}")
  public HttpResponse delete(String id) {
    var forbidden = requireAdmin();
    if (forbidden != null) return forbidden;
    cc.forKeyValueEntity(id).method(UserGroupEntity::delete).invoke();
    return HttpResponses.ok(java.util.Map.of("status", "deleted"));
  }

  public record SetUsersRequest(List<String> userIds) {}

  @Put("/user-groups/{id}/users")
  public HttpResponse setUsers(String id, SetUsersRequest body) {
    var forbidden = requireAdmin();
    if (forbidden != null) return forbidden;
    var g = cc.forKeyValueEntity(id).method(UserGroupEntity::setUsers)
        .invoke(new UserGroupEntity.SetUsers(body.userIds(), Instant.now().toEpochMilli()));
    // Keep the user side of the many-to-many consistent, matching user_group_service.go's
    // reciprocal update rather than requiring two separate admin calls to stay in sync.
    for (var u : cc.forView().method(UsersView::all).invoke().users()) {
      boolean shouldHave = body.userIds().contains(u.id());
      boolean has = u.groupIds().contains(id);
      if (shouldHave != has) {
        var newGroups = new java.util.ArrayList<>(u.groupIds());
        if (shouldHave) newGroups.add(id); else newGroups.remove(id);
        cc.forKeyValueEntity(u.id()).method(io.akka.pocketid.application.UserEntity::setGroups)
            .invoke(new io.akka.pocketid.application.UserEntity.SetGroups(newGroups, Instant.now().toEpochMilli()));
      }
    }
    return HttpResponses.ok(toDto(g));
  }

  public record SetAllowedClientsRequest(List<String> oidcClientIds) {}

  @Put("/user-groups/{id}/allowed-oidc-clients")
  public HttpResponse setAllowedClients(String id, SetAllowedClientsRequest body) {
    var forbidden = requireAdmin();
    if (forbidden != null) return forbidden;
    var g = cc.forKeyValueEntity(id).method(UserGroupEntity::setAllowedClients)
        .invoke(new UserGroupEntity.SetAllowedClients(body.oidcClientIds(), Instant.now().toEpochMilli()));
    return HttpResponses.ok(toDto(g));
  }
}
