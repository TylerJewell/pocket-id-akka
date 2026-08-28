package io.akka.pocketid.api;

import akka.http.javadsl.model.HttpResponse;
import akka.http.javadsl.model.StatusCodes;
import akka.javasdk.annotations.Acl;
import akka.javasdk.annotations.http.Get;
import akka.javasdk.annotations.http.HttpEndpoint;
import akka.javasdk.annotations.http.Post;
import akka.javasdk.client.ComponentClient;
import akka.javasdk.http.AbstractHttpEndpoint;
import akka.javasdk.http.HttpResponses;
import io.akka.pocketid.application.ApiKeyEntity;
import io.akka.pocketid.application.ApiKeysView;
import io.akka.pocketid.application.AppConfigEntity;
import io.akka.pocketid.application.BackupService;
import io.akka.pocketid.application.MaintenanceLockEntity;
import io.akka.pocketid.application.OidcClientEntity;
import io.akka.pocketid.application.OidcClientsView;
import io.akka.pocketid.application.UserEntity;
import io.akka.pocketid.application.UserGroupEntity;
import io.akka.pocketid.application.UserGroupsView;
import io.akka.pocketid.application.UsersView;
import io.akka.pocketid.domain.ApiKeyRecord;
import io.akka.pocketid.domain.OidcClient;
import io.akka.pocketid.domain.User;
import io.akka.pocketid.domain.UserGroup;
import java.time.Instant;
import java.util.Base64;
import java.util.Map;

/**
 * `pocket-id export` / `pocket-id import`, moved from a standalone CLI subcommand (the source
 * runs these against the DB directly, offline) to an admin HTTP surface — this port's services
 * are HTTP-first (SPEC-001), and the entities backing every record here are only reachable
 * through {@link ComponentClient}, which requires the running service, not a detached process.
 * {@code pocket-id-port/method/proposal.md} covers a matching standalone CLI wrapper
 * (`io.akka.pocketid.cli.PocketIdCli`) that drives this same endpoint pair over real HTTP,
 * satisfying "a CLI is in scope" without requiring direct DB access this port's components don't
 * expose.
 */
@Acl(allow = @Acl.Matcher(principal = Acl.Principal.ALL))
@HttpEndpoint("/api/admin/backup")
public class BackupEndpoint extends AbstractHttpEndpoint {

  private final ComponentClient cc;

  public BackupEndpoint(ComponentClient cc) { this.cc = cc; }

  private boolean isAdmin() {
    var u = AuthSupport.authenticatedUser(requestContext(), cc);
    return u != null && u.isAdmin();
  }

  /** The ZIP is returned base64-encoded in a JSON envelope rather than as a raw
   * {@code application/octet-stream} body, matching every other binary payload this port's data
   * layer already carries this way (image/logo/picture uploads) — a CLI wrapper decodes the one
   * field to bytes exactly as it already must for those. */
  public record ExportResponse(String base64Zip) {}

  @Get("/export")
  public HttpResponse export() {
    if (!isAdmin()) return HttpResponses.ok(Map.of("error", "forbidden")).withStatus(StatusCodes.FORBIDDEN);
    var config = cc.forKeyValueEntity("singleton").method(AppConfigEntity::get).invoke();
    var users = cc.forView().method(UsersView::all).invoke().users();
    var groups = cc.forView().method(UserGroupsView::all).invoke().groups();
    var clients = cc.forView().method(OidcClientsView::all).invoke().clients();
    var apiKeys = cc.forView().method(ApiKeysView::all).invoke().keys();
    byte[] zip = BackupService.toZip(new BackupService.Bundle(config, users, groups, clients, apiKeys));
    return HttpResponses.ok(new ExportResponse(Base64.getEncoder().encodeToString(zip)));
  }

  public record ImportRequest(String base64Zip) {}

  /** Wipes every user, group, client and API key currently on record and restores the bundle's
   * own set in their place — `import.go`'s "wipes and recreates the schema" — then applies the
   * bundle's app configuration. Guarded by {@link MaintenanceLockEntity} so two imports cannot
   * interleave their wipe-then-restore against each other; see that class's doc for how this
   * narrows the source's actor-cluster-wide exclusive lock to this single running instance. */
  @Post("/import")
  public HttpResponse importBackup(ImportRequest body) {
    if (!isAdmin()) return HttpResponses.ok(Map.of("error", "forbidden")).withStatus(StatusCodes.FORBIDDEN);
    long now = Instant.now().toEpochMilli();
    boolean acquired = cc.forKeyValueEntity("singleton").method(MaintenanceLockEntity::tryAcquire).invoke(now);
    if (!acquired) {
      return HttpResponses.ok(Map.of("error", "An import is already in progress.")).withStatus(StatusCodes.CONFLICT);
    }
    try {
      var bundle = BackupService.fromZip(Base64.getDecoder().decode(body.base64Zip()));

      // A KeyValueEntity's deleteEntity() is permanent in this SDK (AK-00205) -- an id the
      // restore step below is about to write again must never be hard-deleted first, or the
      // restore itself fails as "changed after deletion". Only ids the bundle does *not*
      // include are deleted; every id the bundle does include is overwritten in place by
      // restore(), which is what "wipe and recreate" means for an id that survives the wipe.
      var bundleUserIds = bundle.users().stream().map(User::id).collect(java.util.stream.Collectors.toSet());
      var bundleGroupIds = bundle.groups().stream().map(UserGroup::id).collect(java.util.stream.Collectors.toSet());
      var bundleClientIds = bundle.clients().stream().map(OidcClient::clientId).collect(java.util.stream.Collectors.toSet());
      var bundleApiKeyIds = bundle.apiKeys().stream().map(ApiKeyRecord::id).collect(java.util.stream.Collectors.toSet());

      for (var u : cc.forView().method(UsersView::all).invoke().users()) {
        if (!bundleUserIds.contains(u.id())) cc.forKeyValueEntity(u.id()).method(UserEntity::delete).invoke();
      }
      for (var g : cc.forView().method(UserGroupsView::all).invoke().groups()) {
        if (!bundleGroupIds.contains(g.id())) cc.forKeyValueEntity(g.id()).method(UserGroupEntity::delete).invoke();
      }
      for (var c : cc.forView().method(OidcClientsView::all).invoke().clients()) {
        if (!bundleClientIds.contains(c.clientId())) cc.forKeyValueEntity(c.clientId()).method(OidcClientEntity::delete).invoke();
      }
      for (var k : cc.forView().method(ApiKeysView::all).invoke().keys()) {
        if (!bundleApiKeyIds.contains(k.id())) cc.forKeyValueEntity(k.id()).method(ApiKeyEntity::delete).invoke();
      }

      for (var u : bundle.users()) cc.forKeyValueEntity(u.id()).method(UserEntity::restore).invoke(u);
      for (var g : bundle.groups()) cc.forKeyValueEntity(g.id()).method(UserGroupEntity::restore).invoke(g);
      for (var c : bundle.clients()) cc.forKeyValueEntity(c.clientId()).method(OidcClientEntity::restore).invoke(c);
      for (var k : bundle.apiKeys()) cc.forKeyValueEntity(k.id()).method(ApiKeyEntity::restore).invoke(k);
      if (!bundle.config().isEmpty()) {
        cc.forKeyValueEntity("singleton").method(AppConfigEntity::update).invoke(new AppConfigEntity.Update(bundle.config()));
      }

      return HttpResponses.ok(Map.of(
          "status", "restored", "users", bundle.users().size(), "groups", bundle.groups().size(),
          "clients", bundle.clients().size(), "apiKeys", bundle.apiKeys().size()));
    } finally {
      cc.forKeyValueEntity("singleton").method(MaintenanceLockEntity::release).invoke();
    }
  }
}
