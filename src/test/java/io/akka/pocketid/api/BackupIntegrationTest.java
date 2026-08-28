package io.akka.pocketid.api;

import static org.assertj.core.api.Assertions.assertThat;

import akka.javasdk.testkit.TestKitSupport;
import io.akka.pocketid.application.UserEntity;
import io.akka.pocketid.application.UserGroupEntity;
import io.akka.pocketid.application.UsersView;
import java.time.Instant;
import java.util.Base64;
import java.util.List;
import org.junit.jupiter.api.Test;

/**
 * `pocket-id export`/`pocket-id import` — a real export ZIP built from live entities, fed back
 * through import, and the restored state checked over real HTTP, not just that the endpoints
 * returned 200.
 */
public class BackupIntegrationTest extends TestKitSupport {

  private static volatile String adminUserId;

  private String setupOrLoginAdmin() {
    if (adminUserId != null) {
      return httpClient.POST("/login").withRequestBody(new OidcEndpoint.LoginRequest(adminUserId))
          .responseBodyAs(OidcEndpoint.LoginResponse.class).invoke().body().session_id();
    }
    var body = new SignupEndpoint.SetupRequest("backup-admin", "backup-admin@example.com", "Admin", "Person");
    var session = httpClient.POST("/api/signup/setup").withRequestBody(body)
        .responseBodyAs(OidcEndpoint.LoginResponse.class).invoke().body();
    adminUserId = session.subject();
    return session.session_id();
  }

  @Test
  void exportedBackupRestoresUsersAndGroupsAfterAWipe() {
    String adminSession = setupOrLoginAdmin();

    componentClient.forKeyValueEntity("backup-group").method(UserGroupEntity::create)
        .invoke(new UserGroupEntity.Create("backup-group", "backup-group", "Backup Group", Instant.now().toEpochMilli()));
    componentClient.forKeyValueEntity("backup-user").method(UserEntity::create).invoke(
        new UserEntity.Create("backup-user", "backup-user", "backup-user@example.com", "Back", "Up", null, false, List.of("backup-group"), Instant.now().toEpochMilli()));

    var exported = httpClient.GET("/api/admin/backup/export").addHeader("X-Session-Id", adminSession)
        .responseBodyAs(BackupEndpoint.ExportResponse.class).invoke().body();
    byte[] zipBytes = Base64.getDecoder().decode(exported.base64Zip());
    assertThat(zipBytes.length).isGreaterThan(0);

    var importResponse = httpClient.POST("/api/admin/backup/import")
        .addHeader("X-Session-Id", adminSession)
        .withRequestBody(new BackupEndpoint.ImportRequest(exported.base64Zip()))
        .invoke().httpResponse();
    assertThat(importResponse.status().intValue()).isEqualTo(200);

    var restoredUser = componentClient.forKeyValueEntity("backup-user").method(UserEntity::get).invoke();
    assertThat(restoredUser.id()).isEqualTo("backup-user");
    assertThat(restoredUser.groupIds()).containsExactly("backup-group");

    var restoredGroup = componentClient.forKeyValueEntity("backup-group").method(UserGroupEntity::get).invoke();
    assertThat(restoredGroup.id()).isEqualTo("backup-group");

    // The admin's own user survives the wipe-then-restore, so the session used to trigger the
    // import is still valid afterward -- the property that makes self-service import possible.
    var stillAdmin = httpClient.GET("/api/users/me").addHeader("X-Session-Id", adminSession).invoke().httpResponse();
    assertThat(stillAdmin.status().intValue()).isEqualTo(200);
  }

  @Test
  void concurrentImportIsRefusedWhileOneIsInProgress() {
    String adminSession = setupOrLoginAdmin();
    var emptyZip = io.akka.pocketid.application.BackupService.toZip(
        new io.akka.pocketid.application.BackupService.Bundle(java.util.Map.of(), List.of(), List.of(), List.of(), List.of()));
    String encoded = Base64.getEncoder().encodeToString(emptyZip);

    boolean acquired = componentClient.forKeyValueEntity("singleton")
        .method(io.akka.pocketid.application.MaintenanceLockEntity::tryAcquire).invoke(Instant.now().toEpochMilli());
    assertThat(acquired).isTrue();
    try {
      var response = httpClient.POST("/api/admin/backup/import")
          .addHeader("X-Session-Id", adminSession)
          .withRequestBody(new BackupEndpoint.ImportRequest(encoded))
          .invoke().httpResponse();
      assertThat(response.status().intValue()).isEqualTo(409);
    } finally {
      componentClient.forKeyValueEntity("singleton").method(io.akka.pocketid.application.MaintenanceLockEntity::release).invoke();
    }
  }
}
