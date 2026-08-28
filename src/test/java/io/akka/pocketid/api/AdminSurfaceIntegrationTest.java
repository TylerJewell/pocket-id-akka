package io.akka.pocketid.api;

import static org.assertj.core.api.Assertions.assertThat;

import akka.javasdk.testkit.TestKitSupport;
import java.util.List;
import java.util.Map;
import org.junit.jupiter.api.Test;

/**
 * Full-system scope (port-log 2026-08-26 session, event B-1) — covers the identity-management
 * surface added beyond the original OIDC-only slice: signup/setup, users, groups, custom
 * claims, API keys, app configuration, and audit logging, all reached over real HTTP the way an
 * external caller would (not through a test-only entity call).
 */
public class AdminSurfaceIntegrationTest extends TestKitSupport {

  /** Views update asynchronously from the entities that back them; a read immediately after a
   * write can observe the pre-update row. Retries rather than sleeping a fixed amount. */
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

  // /signup/setup only succeeds once per running service; the admin's id is remembered here so
  // later test methods in this class can re-establish a session instead of retrying setup.
  private static volatile String adminUserId;

  private String setupInitialAdmin() {
    if (adminUserId != null) {
      var login = httpClient.POST("/login")
          .withRequestBody(new OidcEndpoint.LoginRequest(adminUserId))
          .responseBodyAs(OidcEndpoint.LoginResponse.class).invoke().body();
      return login.session_id();
    }
    var body = new SignupEndpoint.SetupRequest("admin", "admin@example.com", "Admin", "Person");
    var session = httpClient.POST("/api/signup/setup").withRequestBody(body)
        .responseBodyAs(OidcEndpoint.LoginResponse.class).invoke().body();
    adminUserId = session.subject();
    return session.session_id();
  }

  @Test
  void setupCreatesTheFirstUserAsAdminAndRefusesASecondSetup() {
    String sessionId = setupInitialAdmin();
    assertThat(sessionId).isNotBlank();

    var status = eventually(
        () -> httpClient.GET("/api/signup/setup").responseBodyAs(Map.class).invoke().body(),
        s -> Boolean.TRUE.equals(s.get("setupCompleted")));
    assertThat(status.get("setupCompleted")).isEqualTo(true);
  }

  @Test
  void adminCanCreateAGroupAndAUserAndAssignMembership() {
    String sessionId = setupInitialAdmin();

    var group = httpClient.POST("/api/user-groups")
        .addHeader("X-Session-Id", sessionId)
        .withRequestBody(new UserGroupEndpoint.UpsertGroup("engineering", "Engineering"))
        .responseBodyAs(Dtos.UserGroupDto.class).invoke().body();
    assertThat(group.id()).isNotBlank();

    var user = httpClient.POST("/api/users")
        .addHeader("X-Session-Id", sessionId)
        .withRequestBody(new UserEndpoint.UpsertUser("bob", "bob@example.com", true, "Bob", "Builder", "Bob Builder", false, "en", false, List.of(group.id())))
        .responseBodyAs(Dtos.UserDto.class).invoke().body();
    assertThat(user.userGroups()).extracting(Dtos.UserGroupMinimal::id).containsExactly(group.id());

    var fetchedGroup = eventually(
        () -> httpClient.GET("/api/user-groups/" + group.id()).addHeader("X-Session-Id", sessionId)
            .responseBodyAs(Dtos.UserGroupDto.class).invoke().body(),
        g -> !g.users().isEmpty());
    assertThat(fetchedGroup.users()).extracting(Dtos.UserMinimal::id).containsExactly(user.id());
  }

  @Test
  void nonAdminCannotListUsers() {
    String sessionId = setupInitialAdmin();
    var user = httpClient.POST("/api/users")
        .addHeader("X-Session-Id", sessionId)
        .withRequestBody(new UserEndpoint.UpsertUser("carol", "carol@example.com", true, "Carol", "Coder", "Carol Coder", false, "en", false, List.of()))
        .responseBodyAs(Dtos.UserDto.class).invoke().body();

    var carolSession = httpClient.POST("/login")
        .withRequestBody(new OidcEndpoint.LoginRequest(user.id()))
        .responseBodyAs(OidcEndpoint.LoginResponse.class).invoke().body();

    var response = httpClient.GET("/api/users").addHeader("X-Session-Id", carolSession.session_id()).invoke().httpResponse();
    assertThat(response.status().intValue()).isEqualTo(403);
  }

  @Test
  void apiKeyAuthenticatesLikeASessionAndExpiredKeysAreRejected() {
    String sessionId = setupInitialAdmin();

    var created = httpClient.POST("/api/api-keys")
        .addHeader("X-Session-Id", sessionId)
        .withRequestBody(new ApiKeyEndpoint.CreateApiKeyRequest("automation", "ci", System.currentTimeMillis() + 3_600_000))
        .responseBodyAs(Map.class).invoke().body();
    String rawKey = (String) created.get("apiKey");
    assertThat(rawKey).isNotBlank();

    var me = eventually(
        () -> httpClient.GET("/api/users/me").addHeader("X-API-KEY", rawKey).invoke().httpResponse().status().intValue(),
        status -> status == 200);
    assertThat(me).isEqualTo(200);

    var expiredCreate = httpClient.POST("/api/api-keys")
        .addHeader("X-Session-Id", sessionId)
        .withRequestBody(new ApiKeyEndpoint.CreateApiKeyRequest("bad", "already expired", System.currentTimeMillis() - 1000))
        .invoke().httpResponse();
    assertThat(expiredCreate.status().intValue()).isEqualTo(400);
  }

  @Test
  void customClaimsRejectReservedKeysAndAreCarriedIntoTheIdToken() throws Exception {
    String sessionId = setupInitialAdmin();
    var user = httpClient.POST("/api/users")
        .addHeader("X-Session-Id", sessionId)
        .withRequestBody(new UserEndpoint.UpsertUser("dave", "dave@example.com", true, "Dave", "Data", "Dave Data", false, "en", false, List.of()))
        .responseBodyAs(Dtos.UserDto.class).invoke().body();

    var rejected = httpClient.PUT("/api/custom-claims/user/" + user.id())
        .addHeader("X-Session-Id", sessionId)
        .withRequestBody(List.of(new io.akka.pocketid.domain.CustomClaim("email", "not-allowed")))
        .invoke().httpResponse();
    assertThat(rejected.status().intValue()).isEqualTo(400);

    var accepted = httpClient.PUT("/api/custom-claims/user/" + user.id())
        .addHeader("X-Session-Id", sessionId)
        .withRequestBody(List.of(new io.akka.pocketid.domain.CustomClaim("department", "engineering")))
        .invoke().httpResponse();
    assertThat(accepted.status().intValue()).isEqualTo(200);
  }

  @Test
  void appConfigUpdateRoundTripsAndResetsOnEmptyString() {
    String sessionId = setupInitialAdmin();
    httpClient.PUT("/api/application-configuration")
        .addHeader("X-Session-Id", sessionId)
        .withRequestBody(new AppConfigEndpoint.ConfigChanges(Map.of("appName", "My Test IdP")))
        .invoke();

    var all = httpClient.GET("/api/application-configuration/all").addHeader("X-Session-Id", sessionId).responseBodyAs(Map.class).invoke().body();
    assertThat(all.get("appName")).isEqualTo("My Test IdP");

    httpClient.PUT("/api/application-configuration")
        .addHeader("X-Session-Id", sessionId)
        .withRequestBody(new AppConfigEndpoint.ConfigChanges(Map.of("appName", "")))
        .invoke();
    var reset = httpClient.GET("/api/application-configuration/all").addHeader("X-Session-Id", sessionId).responseBodyAs(Map.class).invoke().body();
    assertThat(reset.get("appName")).isEqualTo("Pocket ID");
  }

  @Test
  @SuppressWarnings("unchecked")
  void keyRotateReplacesTheSigningKeyAndInvalidatesTokensSignedByThePreviousOne() throws Exception {
    // `pocket-id key-rotate`'s equivalent (SigningKeyEntity) — non-admin is refused, an admin's
    // rotation changes the published JWKS kid, and a token minted before rotation no longer
    // verifies against the new key (SigningKeys.verify uses whichever key is currently persisted).
    String sessionId = setupInitialAdmin();

    var before = httpClient.GET("/.well-known/jwks.json").responseBodyAs(Map.class).invoke().body();
    String kidBefore = (String) ((List<Map<String, Object>>) before.get("keys")).get(0).get("kid");

    var claims = new com.nimbusds.jwt.JWTClaimsSet.Builder().subject("alice").expirationTime(
        java.util.Date.from(java.time.Instant.now().plusSeconds(60))).build();
    String tokenBeforeRotation = io.akka.pocketid.application.SigningKeys.sign(componentClient, claims);
    assertThat(io.akka.pocketid.application.SigningKeys.verify(componentClient, tokenBeforeRotation)).isNotNull();

    var forbidden = httpClient.POST("/api/application-configuration/rotate-signing-key").invoke().httpResponse();
    assertThat(forbidden.status().intValue()).isEqualTo(403);

    httpClient.POST("/api/application-configuration/rotate-signing-key")
        .addHeader("X-Session-Id", sessionId).invoke();

    var after = httpClient.GET("/.well-known/jwks.json").responseBodyAs(Map.class).invoke().body();
    String kidAfter = (String) ((List<Map<String, Object>>) after.get("keys")).get(0).get("kid");
    assertThat(kidAfter).isNotEqualTo(kidBefore);

    assertThat(io.akka.pocketid.application.SigningKeys.verify(componentClient, tokenBeforeRotation)).isNull();
  }

  @Test
  @SuppressWarnings("unchecked")
  void encryptionKeyRotateReencryptsTheSigningKeyAndScimTokensWithoutChangingTheirValues() throws Exception {
    // `pocket-id encryption-key-rotate` — re-wraps every at-rest secret (persisted signing key,
    // SCIM bearer tokens) under a new master key. Unlike /rotate-signing-key, the underlying
    // secret values themselves must NOT change: a token signed before the call still verifies,
    // and a SCIM sync run after the call still authenticates with the same bearer token.
    //
    // Rotates to the *same* master key the running process already has (self-rotation) rather
    // than a genuinely different one: this test shares one running service instance with every
    // other test in the suite (setupInitialAdmin's cached adminUserId), and the real endpoint's
    // contract — stated in its own Javadoc — is that ciphertext rewrapped under a different key
    // is only decryptable again once the operator sets ENCRYPTION_KEY to that new value and
    // restarts, which this test process cannot do to itself mid-suite. Self-rotation still
    // exercises the real decrypt-then-reencrypt code path end to end (EncryptionSupportTest
    // covers the cross-key case in isolation, where corrupting shared state is not a risk).
    String sessionId = setupInitialAdmin();
    String sameKey = io.akka.pocketid.application.EncryptionSupport.currentMasterKey();

    var claims = new com.nimbusds.jwt.JWTClaimsSet.Builder().subject("erin").expirationTime(
        java.util.Date.from(java.time.Instant.now().plusSeconds(60))).build();
    String tokenBeforeRotation = io.akka.pocketid.application.SigningKeys.sign(componentClient, claims);
    assertThat(io.akka.pocketid.application.SigningKeys.verify(componentClient, tokenBeforeRotation)).isNotNull();

    var client = httpClient.POST("/api/oidc/clients")
        .addHeader("X-Session-Id", sessionId)
        .withRequestBody(new OidcClientAdminEndpoint.CreateClientRequest(
            "enc-key-rotate-target", "d", false, List.of("https://rp3.example/cb"), List.of()))
        .responseBodyAs(Map.class).invoke().body();
    String clientId = (String) client.get("id");

    List<String> receivedAuth = new java.util.concurrent.CopyOnWriteArrayList<>();
    var stub = com.sun.net.httpserver.HttpServer.create(new java.net.InetSocketAddress("127.0.0.1", 0), 0);
    stub.createContext("/Users", exchange -> {
      receivedAuth.add(exchange.getRequestHeaders().getFirst("Authorization"));
      byte[] response = "{}".getBytes(java.nio.charset.StandardCharsets.UTF_8);
      exchange.sendResponseHeaders(201, response.length);
      exchange.getResponseBody().write(response);
      exchange.close();
    });
    stub.start();
    try {
      String endpointUrl = "http://127.0.0.1:" + stub.getAddress().getPort();
      var provider = httpClient.POST("/api/scim/service-provider")
          .addHeader("X-Session-Id", sessionId)
          .withRequestBody(new java.util.LinkedHashMap<>(Map.of(
              "oidcClientId", clientId, "endpointUrl", endpointUrl, "bearerToken", "rotate-me-token")))
          .responseBodyAs(io.akka.pocketid.domain.ServiceProvider.class).invoke().body();

      // ServiceProvidersView updates asynchronously from ServiceProviderEntity; the rotate
      // endpoint enumerates providers through that view, so it can race the create above.
      eventually(
          () -> componentClient.forView().method(io.akka.pocketid.application.ServiceProvidersView::all).invoke().items().size(),
          size -> size >= 1);

      var forbidden = httpClient.POST("/api/application-configuration/rotate-encryption-key")
          .withRequestBody(new AppConfigEndpoint.RotateEncryptionKeyRequest(sameKey))
          .invoke().httpResponse();
      assertThat(forbidden.status().intValue()).isEqualTo(403);

      var rotated = httpClient.POST("/api/application-configuration/rotate-encryption-key")
          .addHeader("X-Session-Id", sessionId)
          .withRequestBody(new AppConfigEndpoint.RotateEncryptionKeyRequest(sameKey))
          .responseBodyAs(Map.class).invoke().body();
      assertThat(((Number) rotated.get("serviceProvidersReencrypted")).intValue()).isGreaterThanOrEqualTo(1);

      assertThat(io.akka.pocketid.application.SigningKeys.verify(componentClient, tokenBeforeRotation)).isNotNull();

      httpClient.POST("/api/scim/service-provider/" + provider.id() + "/sync")
          .addHeader("X-Session-Id", sessionId).invoke();
      assertThat(receivedAuth).contains("Bearer rotate-me-token");
    } finally {
      stub.stop(0);
    }
  }

  /** RENDERING.md R4/R5 appearance comparison against the running original (gui/manifest.json,
   * 2026-08-27 session) found the login/setup/device screens' background pane blank on the port:
   * app_images_bootstrap.go seeds background.webp/favicon.ico/logoEmail.png into the source's
   * image store on first boot, and nothing here did the equivalent, so a fresh install's
   * GET /api/application-images/background 404'd where the source returns the bundled photo. */
  @Test
  void defaultBackgroundFaviconAndEmailImagesServeUntilOverriddenOrDeleted() {
    var background = httpClient.GET("/api/application-images/background").invoke();
    assertThat(background.httpResponse().status().intValue()).isEqualTo(200);
    assertThat(background.httpResponse().entity().getContentType().toString()).contains("webp");

    var favicon = httpClient.GET("/api/application-images/favicon").invoke();
    assertThat(favicon.httpResponse().status().intValue()).isEqualTo(200);

    var email = httpClient.GET("/api/application-images/email").invoke();
    assertThat(email.httpResponse().status().intValue()).isEqualTo(200);

    String sessionId = setupInitialAdmin();
    String uploaded = java.util.Base64.getEncoder().encodeToString("not-a-real-image".getBytes());
    httpClient.PUT("/api/application-images/background")
        .addHeader("X-Session-Id", sessionId)
        .withRequestBody(new AppConfigEndpoint.ImageUpload(uploaded, "image/png"))
        .invoke();
    var afterUpload = httpClient.GET("/api/application-images/background").invoke();
    assertThat(afterUpload.httpResponse().status().intValue()).isEqualTo(200);
    assertThat(afterUpload.httpResponse().entity().getContentType().toString()).contains("png");

    httpClient.DELETE("/api/application-images/background").addHeader("X-Session-Id", sessionId).invoke();
    var afterDelete = httpClient.GET("/api/application-images/background").invoke();
    assertThat(afterDelete.httpResponse().status().intValue()).isEqualTo(404);
  }
}
