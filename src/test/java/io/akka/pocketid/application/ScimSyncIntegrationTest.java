package io.akka.pocketid.application;

import static org.assertj.core.api.Assertions.assertThat;

import akka.javasdk.testkit.TestKitSupport;
import com.sun.net.httpserver.HttpServer;
import io.akka.pocketid.api.ApiKeyEndpoint;
import io.akka.pocketid.api.Dtos;
import io.akka.pocketid.api.OidcClientAdminEndpoint;
import io.akka.pocketid.api.OidcEndpoint;
import io.akka.pocketid.api.SignupEndpoint;
import io.akka.pocketid.api.UserEndpoint;
import io.akka.pocketid.api.UserGroupEndpoint;
import java.net.InetSocketAddress;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.concurrent.CopyOnWriteArrayList;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;

/**
 * SPEC-001 §6.11 — {@link ScimSync} makes a real outbound SCIM 2.0 HTTP call; this drives it
 * against a real (stub) SCIM server rather than asserting on the request-building code alone,
 * per PIPELINE.md's "run it" rule.
 */
public class ScimSyncIntegrationTest extends TestKitSupport {

  private static volatile String adminUserId;
  private HttpServer stub;

  @AfterEach
  void stopStub() {
    if (stub != null) stub.stop(0);
  }

  private String setupInitialAdmin() {
    if (adminUserId != null) {
      var login = httpClient.POST("/login")
          .withRequestBody(new OidcEndpoint.LoginRequest(adminUserId))
          .responseBodyAs(OidcEndpoint.LoginResponse.class).invoke().body();
      return login.session_id();
    }
    var body = new SignupEndpoint.SetupRequest("scimadmin", "scimadmin@example.com", "Scim", "Admin");
    var session = httpClient.POST("/api/signup/setup").withRequestBody(body)
        .responseBodyAs(OidcEndpoint.LoginResponse.class).invoke().body();
    adminUserId = session.subject();
    return session.session_id();
  }

  @Test
  void syncPushesEveryAllowedUserToTheRemoteScimEndpoint() throws Exception {
    String sessionId = setupInitialAdmin();

    var client = httpClient.POST("/api/oidc/clients")
        .addHeader("X-Session-Id", sessionId)
        .withRequestBody(new OidcClientAdminEndpoint.CreateClientRequest(
            "scim-target", "d", false, List.of("https://rp.example/cb"), List.of()))
        .responseBodyAs(Map.class).invoke().body();
    String clientId = (String) client.get("id");

    var group = httpClient.POST("/api/user-groups")
        .addHeader("X-Session-Id", sessionId)
        .withRequestBody(new UserGroupEndpoint.UpsertGroup("scim-target-group", "Scim Target Group"))
        .responseBodyAs(Dtos.UserGroupDto.class).invoke().body();
    httpClient.PUT("/api/oidc/clients/" + clientId + "/allowed-user-groups")
        .addHeader("X-Session-Id", sessionId)
        .withRequestBody(new OidcClientAdminEndpoint.SetAllowedGroupsRequest(true, List.of(group.id())))
        .invoke();

    // Group-restricted to a group containing only this one user, so the push this test asserts
    // on is not diluted by other users this TestKit instance's earlier tests already created.
    var user = httpClient.POST("/api/users")
        .addHeader("X-Session-Id", sessionId)
        .withRequestBody(new UserEndpoint.UpsertUser(
            "scimuser", "scimuser@example.com", true, "Scim", "User", "Scim User", false, "en", false, List.of(group.id())))
        .responseBodyAs(Dtos.UserDto.class).invoke().body();
    waitUntilVisibleInUsersView(sessionId, user.id());

    List<String> receivedBodies = new CopyOnWriteArrayList<>();
    List<String> receivedAuth = new CopyOnWriteArrayList<>();
    stub = HttpServer.create(new InetSocketAddress("127.0.0.1", 0), 0);
    stub.createContext("/Users", exchange -> {
      byte[] bodyBytes = exchange.getRequestBody().readAllBytes();
      receivedBodies.add(new String(bodyBytes, StandardCharsets.UTF_8));
      receivedAuth.add(exchange.getRequestHeaders().getFirst("Authorization"));
      byte[] response = "{}".getBytes(StandardCharsets.UTF_8);
      exchange.sendResponseHeaders(201, response.length);
      exchange.getResponseBody().write(response);
      exchange.close();
    });
    stub.start();
    String endpointUrl = "http://127.0.0.1:" + stub.getAddress().getPort();

    var provider = httpClient.POST("/api/scim/service-provider")
        .addHeader("X-Session-Id", sessionId)
        .withRequestBody(new java.util.LinkedHashMap<>(Map.of(
            "oidcClientId", clientId, "endpointUrl", endpointUrl, "bearerToken", "secret-token")))
        .responseBodyAs(io.akka.pocketid.domain.ServiceProvider.class).invoke().body();
    assertThat(provider.id()).isNotBlank();

    var syncResult = httpClient.POST("/api/scim/service-provider/" + provider.id() + "/sync")
        .addHeader("X-Session-Id", sessionId)
        .responseBodyAs(Map.class).invoke().body();

    assertThat(((Number) syncResult.get("usersPushed")).intValue()).isEqualTo(1);
    assertThat((List<?>) syncResult.get("errors")).isEmpty();
    assertThat(receivedBodies).hasSize(1);
    assertThat(receivedBodies.get(0)).contains("\"userName\":\"scimuser\"").contains("scimuser@example.com");
    assertThat(receivedAuth.get(0)).isEqualTo("Bearer secret-token");
  }

  @Test
  void aFailingRemoteEndpointIsReportedAsAnErrorNotAThrow() throws Exception {
    String sessionId = setupInitialAdmin();

    var client = httpClient.POST("/api/oidc/clients")
        .addHeader("X-Session-Id", sessionId)
        .withRequestBody(new OidcClientAdminEndpoint.CreateClientRequest(
            "scim-target-2", "d", false, List.of("https://rp2.example/cb"), List.of()))
        .responseBodyAs(Map.class).invoke().body();
    String clientId = (String) client.get("id");

    var group = httpClient.POST("/api/user-groups")
        .addHeader("X-Session-Id", sessionId)
        .withRequestBody(new UserGroupEndpoint.UpsertGroup("scim-target-group-2", "Scim Target Group 2"))
        .responseBodyAs(Dtos.UserGroupDto.class).invoke().body();
    httpClient.PUT("/api/oidc/clients/" + clientId + "/allowed-user-groups")
        .addHeader("X-Session-Id", sessionId)
        .withRequestBody(new OidcClientAdminEndpoint.SetAllowedGroupsRequest(true, List.of(group.id())))
        .invoke();

    var flaky = httpClient.POST("/api/users")
        .addHeader("X-Session-Id", sessionId)
        .withRequestBody(new UserEndpoint.UpsertUser(
            "flakyuser", "flaky@example.com", true, "Flaky", "User", "Flaky User", false, "en", false, List.of(group.id())))
        .responseBodyAs(Dtos.UserDto.class).invoke().body();
    waitUntilVisibleInUsersView(sessionId, flaky.id());

    stub = HttpServer.create(new InetSocketAddress("127.0.0.1", 0), 0);
    stub.createContext("/Users", exchange -> {
      exchange.sendResponseHeaders(500, -1);
      exchange.close();
    });
    stub.start();
    String endpointUrl = "http://127.0.0.1:" + stub.getAddress().getPort();

    var provider = httpClient.POST("/api/scim/service-provider")
        .addHeader("X-Session-Id", sessionId)
        .withRequestBody(new java.util.LinkedHashMap<>(Map.of(
            "oidcClientId", clientId, "endpointUrl", endpointUrl, "bearerToken", "t")))
        .responseBodyAs(io.akka.pocketid.domain.ServiceProvider.class).invoke().body();

    var syncResult = httpClient.POST("/api/scim/service-provider/" + provider.id() + "/sync")
        .addHeader("X-Session-Id", sessionId)
        .responseBodyAs(Map.class).invoke().body();

    assertThat(((Number) syncResult.get("usersPushed")).intValue()).isEqualTo(0);
    assertThat((List<?>) syncResult.get("errors")).hasSize(1);
  }

  /** UsersView updates asynchronously from UserEntity; ScimSync reads through the view, so a
   * sync run immediately after creating a user can race it. Retries rather than sleeping a
   * fixed amount. */
  private void waitUntilVisibleInUsersView(String sessionId, String userId) {
    for (int i = 0; i < 100; i++) {
      var all = httpClient.GET("/api/users").addHeader("X-Session-Id", sessionId)
          .responseBodyAs(Dtos.Page.class).invoke().body();
      boolean visible = all.data().stream().anyMatch(u -> userId.equals(((Map<?, ?>) u).get("id")));
      if (visible) return;
      try {
        Thread.sleep(100);
      } catch (InterruptedException e) {
        Thread.currentThread().interrupt();
        return;
      }
    }
  }
}
