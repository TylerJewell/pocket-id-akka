package io.akka.pocketid.application;

import static org.assertj.core.api.Assertions.assertThat;

import akka.javasdk.testkit.TestKitSupport;
import com.unboundid.ldap.listener.InMemoryDirectoryServer;
import com.unboundid.ldap.listener.InMemoryDirectoryServerConfig;
import com.unboundid.ldap.listener.InMemoryListenerConfig;
import com.unboundid.ldap.sdk.Entry;
import io.akka.pocketid.api.AppConfigEndpoint;
import io.akka.pocketid.api.Dtos;
import io.akka.pocketid.api.OidcEndpoint;
import io.akka.pocketid.api.SignupEndpoint;
import java.util.List;
import java.util.Map;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;

/**
 * SPEC-001 §6.10 — {@link LdapSync} binds to and searches a real directory over the wire; this
 * drives it against a real (in-memory) LDAP server rather than asserting on the query-building
 * code alone, per PIPELINE.md's "run it" rule. The doc comment on {@link LdapSync} has claimed
 * this test's existence since the 2026-08-26 session; this is that test.
 */
public class LdapSyncIntegrationTest extends TestKitSupport {

  private InMemoryDirectoryServer directory;
  private static volatile String adminUserId;

  @AfterEach
  void stopDirectory() {
    if (directory != null) directory.shutDown(true);
  }

  private String setupInitialAdmin() {
    if (adminUserId != null) {
      var login = httpClient.POST("/login")
          .withRequestBody(new OidcEndpoint.LoginRequest(adminUserId))
          .responseBodyAs(OidcEndpoint.LoginResponse.class).invoke().body();
      return login.session_id();
    }
    var body = new SignupEndpoint.SetupRequest("ldapadmin", "ldapadmin@example.com", "Ldap", "Admin");
    var session = httpClient.POST("/api/signup/setup").withRequestBody(body)
        .responseBodyAs(OidcEndpoint.LoginResponse.class).invoke().body();
    adminUserId = session.subject();
    return session.session_id();
  }

  private InMemoryDirectoryServer startDirectory() throws Exception {
    var config = new InMemoryDirectoryServerConfig("dc=example,dc=com");
    config.setSchema(null); // the source's own "uuid" identifier attribute is not standard LDAP schema
    config.setListenerConfigs(InMemoryListenerConfig.createLDAPConfig("default", 0));
    var server = new InMemoryDirectoryServer(config);
    server.add(new Entry("dn: dc=example,dc=com", "objectClass: domain", "dc: example"));
    server.add(new Entry(
        "dn: uid=alice,dc=example,dc=com",
        "objectClass: person",
        "objectClass: inetOrgPerson",
        "uid: alice",
        "cn: Alice Example",
        "sn: Example",
        "givenName: Alice",
        "mail: alice@example.com",
        "uuid: ldap-alice-1"));
    server.add(new Entry(
        "dn: cn=engineers,dc=example,dc=com",
        "objectClass: groupOfNames",
        "objectClass: top",
        "cn: engineers",
        "member: uid=alice,dc=example,dc=com",
        "uuid: ldap-group-1"));
    server.startListening();
    return server;
  }

  @Test
  void syncCreatesUsersAndGroupsFoundInTheDirectoryAndUpdatesThemOnASecondRun() throws Exception {
    String sessionId = setupInitialAdmin();
    directory = startDirectory();
    int port = directory.getListenPort();

    httpClient.PUT("/api/application-configuration")
        .addHeader("X-Session-Id", sessionId)
        .withRequestBody(new AppConfigEndpoint.ConfigChanges(Map.of(
            "ldapEnabled", "true",
            "ldapUrl", "ldap://127.0.0.1:" + port,
            "ldapBase", "dc=example,dc=com")))
        .invoke();

    var firstSync = httpClient.POST("/api/application-configuration/sync-ldap")
        .addHeader("X-Session-Id", sessionId)
        .responseBodyAs(Map.class).invoke().body();
    assertThat(((Number) firstSync.get("usersSynced")).intValue()).isEqualTo(1);
    assertThat(((Number) firstSync.get("groupsSynced")).intValue()).isEqualTo(1);

    var users = eventually(
        () -> httpClient.GET("/api/users").addHeader("X-Session-Id", sessionId)
            .responseBodyAs(Dtos.Page.class).invoke().body(),
        p -> p.data().stream().anyMatch(u -> "alice".equals(((Map<?, ?>) u).get("username"))));
    var alice = (Map<?, ?>) users.data().stream()
        .filter(u -> "alice".equals(((Map<?, ?>) u).get("username")))
        .findFirst().orElseThrow();
    assertThat(alice.get("email")).isEqualTo("alice@example.com");

    var groups = eventually(
        () -> httpClient.GET("/api/user-groups").addHeader("X-Session-Id", sessionId)
            .responseBodyAs(Dtos.Page.class).invoke().body(),
        p -> p.data().stream().anyMatch(g -> "ldap:ldap-group-1".equals(((Map<?, ?>) g).get("name"))));
    assertThat(groups.data()).anySatisfy(g -> assertThat(((Map<?, ?>) g).get("name")).isEqualTo("ldap:ldap-group-1"));

    // Change alice's mail in the directory and sync again — the existing local user is updated,
    // not duplicated, because the reconcile key is the LDAP unique identifier, not the username.
    directory.modify("uid=alice,dc=example,dc=com", new com.unboundid.ldap.sdk.Modification(
        com.unboundid.ldap.sdk.ModificationType.REPLACE, "mail", "alice.updated@example.com"));

    var secondSync = httpClient.POST("/api/application-configuration/sync-ldap")
        .addHeader("X-Session-Id", sessionId)
        .responseBodyAs(Map.class).invoke().body();
    assertThat(((Number) secondSync.get("usersSynced")).intValue()).isEqualTo(1);

    var updatedUsers = eventually(
        () -> httpClient.GET("/api/users").addHeader("X-Session-Id", sessionId)
            .responseBodyAs(Dtos.Page.class).invoke().body(),
        p -> p.data().stream().anyMatch(u -> "alice.updated@example.com".equals(((Map<?, ?>) u).get("email"))));
    long aliceRows = updatedUsers.data().stream()
        .filter(u -> "alice".equals(((Map<?, ?>) u).get("username"))).count();
    assertThat(aliceRows).as("second sync updates the existing alice row instead of creating a duplicate").isEqualTo(1);
  }

  @Test
  void syncIsANoOpWhenLdapIsNotEnabled() {
    String sessionId = setupInitialAdmin();
    var response = httpClient.POST("/api/application-configuration/sync-ldap")
        .addHeader("X-Session-Id", sessionId)
        .invoke().httpResponse();
    assertThat(response.status().intValue()).isEqualTo(400);
  }

  private static <T> T eventually(java.util.function.Supplier<T> read, java.util.function.Predicate<T> ready) {
    T last = null;
    for (int i = 0; i < 100; i++) {
      last = read.get();
      if (ready.test(last)) return last;
      try {
        Thread.sleep(100);
      } catch (InterruptedException e) {
        Thread.currentThread().interrupt();
        break;
      }
    }
    return last;
  }
}
