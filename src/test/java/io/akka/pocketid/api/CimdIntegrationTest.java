package io.akka.pocketid.api;

import static org.assertj.core.api.Assertions.assertThat;

import akka.javasdk.testkit.TestKitSupport;
import com.sun.net.httpserver.HttpServer;
import io.akka.pocketid.application.AppConfigEntity;
import io.akka.pocketid.application.UserEntity;
import io.akka.pocketid.application.UserGroupEntity;
import java.net.InetSocketAddress;
import java.net.URI;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.time.Instant;
import java.util.Base64;
import java.util.List;
import java.util.UUID;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

/**
 * CIMD (Client ID Metadata Documents) — `cimd.go`'s dynamic client resolution, where the
 * {@code client_id} of an {@code /authorize} request is itself the URL of a JSON document
 * describing the client. There is no real third party to depend on here (the URL is entirely
 * caller-supplied), so this stands up its own throwaway local HTTP server as "the client's own
 * metadata host" — a fair stand-in per PIPELINE.md, since the subject under test is this port's
 * resolver, not whatever server happens to host a document in production.
 */
public class CimdIntegrationTest extends TestKitSupport {

  private HttpServer server;
  private String baseUrl;

  @BeforeEach
  void startServerAndSeed() throws Exception {
    server = HttpServer.create(new InetSocketAddress("127.0.0.1", 0), 0);
    server.createContext("/valid-client.json", exchange -> {
      String body = """
          {"client_name":"CIMD Test Client","token_endpoint_auth_method":"none",
           "grant_types":["authorization_code"],"response_types":["code"],
           "redirect_uris":["http://localhost:9999/callback"]}""";
      byte[] bytes = body.getBytes(StandardCharsets.UTF_8);
      exchange.sendResponseHeaders(200, bytes.length);
      exchange.getResponseBody().write(bytes);
      exchange.close();
    });
    server.createContext("/invalid-client.json", exchange -> {
      String body = """
          {"token_endpoint_auth_method":"client_secret_post",
           "grant_types":["authorization_code"],"response_types":["code"],
           "redirect_uris":["http://localhost:9999/callback"]}""";
      byte[] bytes = body.getBytes(StandardCharsets.UTF_8);
      exchange.sendResponseHeaders(200, bytes.length);
      exchange.getResponseBody().write(bytes);
      exchange.close();
    });
    server.start();
    baseUrl = "http://127.0.0.1:" + server.getAddress().getPort();

    var existingGroup = componentClient.forKeyValueEntity("everyone").method(UserGroupEntity::get).invoke();
    if (existingGroup.id() == null) {
      componentClient.forKeyValueEntity("everyone").method(UserGroupEntity::create)
          .invoke(new UserGroupEntity.Create("everyone", "everyone", "Everyone", Instant.now().toEpochMilli()));
    }
    var existingUser = componentClient.forKeyValueEntity("cimd-alice").method(UserEntity::get).invoke();
    if (existingUser.id() == null) {
      componentClient.forKeyValueEntity("cimd-alice").method(UserEntity::create).invoke(
          new UserEntity.Create("cimd-alice", "cimd-alice", "cimd-alice@example.com", "Alice", "Anderson", "Alice Anderson", false, List.of("everyone"), Instant.now().toEpochMilli()));
    }
  }

  @AfterEach
  void stopServer() {
    server.stop(0);
  }

  private void allowlist(String... urls) {
    String adminSession = setupOrLoginAdmin();
    String json = "[" + String.join(",", java.util.Arrays.stream(urls).map(u -> "\"" + u + "\"").toArray(String[]::new)) + "]";
    httpClient.PUT("/api/application-configuration")
        .addHeader("X-Session-Id", adminSession)
        .withRequestBody(new AppConfigEndpoint.ConfigChanges(java.util.Map.of("cimdUrlAllowlist", json)))
        .invoke();
  }

  private static volatile String adminUserId;

  private String setupOrLoginAdmin() {
    if (adminUserId != null) {
      return httpClient.POST("/login").withRequestBody(new OidcEndpoint.LoginRequest(adminUserId))
          .responseBodyAs(OidcEndpoint.LoginResponse.class).invoke().body().session_id();
    }
    var body = new SignupEndpoint.SetupRequest("cimd-admin", "cimd-admin@example.com", "Admin", "Person");
    var session = httpClient.POST("/api/signup/setup").withRequestBody(body)
        .responseBodyAs(OidcEndpoint.LoginResponse.class).invoke().body();
    adminUserId = session.subject();
    return session.session_id();
  }

  private String login(String subject) {
    return httpClient.POST("/login").withRequestBody(new OidcEndpoint.LoginRequest(subject))
        .responseBodyAs(OidcEndpoint.LoginResponse.class).invoke().body().session_id();
  }

  private record CodePair(String verifier, String challenge) {}

  private CodePair newPkcePair() throws Exception {
    String verifier = UUID.randomUUID().toString() + UUID.randomUUID();
    var digest = MessageDigest.getInstance("SHA-256").digest(verifier.getBytes(StandardCharsets.US_ASCII));
    String challenge = Base64.getUrlEncoder().withoutPadding().encodeToString(digest);
    return new CodePair(verifier, challenge);
  }

  @Test
  void allowlistedCimdUrlResolvesToARealClientAndIssuesACode() throws Exception {
    String clientUrl = baseUrl + "/valid-client.json";
    allowlist(clientUrl);
    String sessionId = login("cimd-alice");
    var pkce = newPkcePair();

    var response = httpClient.GET("/authorize")
        .addHeader("X-Session-Id", sessionId)
        .addQueryParameter("response_type", "code")
        .addQueryParameter("client_id", clientUrl)
        .addQueryParameter("redirect_uri", "http://localhost:9999/callback")
        .addQueryParameter("scope", "openid")
        .addQueryParameter("state", "s1")
        .addQueryParameter("code_challenge", pkce.challenge())
        .addQueryParameter("code_challenge_method", "S256")
        .invoke().httpResponse();

    assertThat(response.status().intValue()).isEqualTo(302);
    String location = response.getHeader("Location").get().value();
    assertThat(location).startsWith("http://localhost:9999/callback");
    assertThat(URI.create(location).getRawQuery()).contains("code=");
  }

  @Test
  void unAllowlistedCimdUrlIsTreatedAsAnUnknownClient() throws Exception {
    String clientUrl = baseUrl + "/valid-client.json"; // real document, but never allowlisted
    String sessionId = login("cimd-alice");
    var pkce = newPkcePair();

    var response = httpClient.GET("/authorize")
        .addHeader("X-Session-Id", sessionId)
        .addQueryParameter("response_type", "code")
        .addQueryParameter("client_id", clientUrl)
        .addQueryParameter("redirect_uri", "http://localhost:9999/callback")
        .addQueryParameter("scope", "openid")
        .addQueryParameter("code_challenge", pkce.challenge())
        .addQueryParameter("code_challenge_method", "S256")
        .invoke().httpResponse();

    assertThat(response.status().intValue()).isEqualTo(400); // rule 3: unknown client never redirects
    assertThat(response.getHeader("Location")).isEmpty();
  }

  @Test
  void aDocumentThatDoesNotUseAuthMethodNoneIsRejected() throws Exception {
    String clientUrl = baseUrl + "/invalid-client.json";
    allowlist(clientUrl);
    String sessionId = login("cimd-alice");
    var pkce = newPkcePair();

    var response = httpClient.GET("/authorize")
        .addHeader("X-Session-Id", sessionId)
        .addQueryParameter("response_type", "code")
        .addQueryParameter("client_id", clientUrl)
        .addQueryParameter("redirect_uri", "http://localhost:9999/callback")
        .addQueryParameter("scope", "openid")
        .addQueryParameter("code_challenge", pkce.challenge())
        .addQueryParameter("code_challenge_method", "S256")
        .invoke().httpResponse();

    assertThat(response.status().intValue()).isEqualTo(400);
  }

  @Test
  void refreshEndpointRefetchesAnAllowlistedDocument() throws Exception {
    String clientUrl = baseUrl + "/valid-client.json";
    allowlist(clientUrl);
    String adminSession = setupOrLoginAdmin();
    String encoded = java.net.URLEncoder.encode(clientUrl, StandardCharsets.UTF_8);

    var response = httpClient.POST("/api/oidc/clients/" + encoded + "/refresh-cimd-metadata")
        .addHeader("X-Session-Id", adminSession)
        .invoke().httpResponse();

    assertThat(response.status().intValue()).isEqualTo(200);
  }
}
