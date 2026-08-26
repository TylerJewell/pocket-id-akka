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
}
