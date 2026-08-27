package io.akka.pocketid.api;

import static org.assertj.core.api.Assertions.assertThat;

import akka.javasdk.testkit.TestKitSupport;
import java.util.List;
import java.util.Map;
import org.junit.jupiter.api.Test;

/**
 * The list/search/sort/pagination query parameters the vendored frontend's
 * {@code ListRequestOptions} (list-request.type.ts) already sends on every admin list request
 * were, until this pass, read nowhere on the server — every list endpoint always returned its
 * view's whole unfiltered set (docs/review-findings.md). This drives real HTTP requests against
 * the real endpoints to check {@link ListQueryParams} is actually wired in, not only unit-tested
 * in isolation — PIPELINE.md's rule that a rule nothing checks by running something is a
 * prediction of a fault, applied to a fix rather than a new feature.
 */
public class ListQueryIntegrationTest extends TestKitSupport {

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

  private static volatile String adminUserId;

  private String setupInitialAdmin() {
    if (adminUserId != null) {
      var login = httpClient.POST("/login")
          .withRequestBody(new OidcEndpoint.LoginRequest(adminUserId))
          .responseBodyAs(OidcEndpoint.LoginResponse.class).invoke().body();
      return login.session_id();
    }
    var body = httpClient.POST("/api/signup/setup")
        .withRequestBody(new SignupEndpoint.SetupRequest("root", "root@example.com", "Root", "Admin"))
        .responseBodyAs(OidcEndpoint.LoginResponse.class).invoke().body();
    adminUserId = body.subject();
    return body.session_id();
  }

  private void createUser(String sessionId, String username, String firstName) {
    httpClient.POST("/api/users")
        .addHeader("X-Session-Id", sessionId)
        .withRequestBody(new UserEndpoint.UpsertUser(
            username, username + "@example.com", true, firstName, "Test", firstName + " Test",
            false, "en", false, List.of()))
        .responseBodyAs(Dtos.UserDto.class).invoke().body();
  }

  @Test
  void usersListSearchesSortsAndPaginates() {
    String sessionId = setupInitialAdmin();
    createUser(sessionId, "alice-lq", "Alice");
    createUser(sessionId, "bob-lq", "Bob");
    createUser(sessionId, "carol-lq", "Carol");

    // search: a substring of the username narrows the result to the matching users only.
    Dtos.Page searched = eventually(
        () -> httpClient.GET("/api/users?search=-lq")
            .addHeader("X-Session-Id", sessionId)
            .responseBodyAs(Dtos.Page.class).invoke().body(),
        p -> p.data().size() >= 3);
    assertThat(searched.data()).hasSize(3);

    var narrowSearch = httpClient.GET("/api/users?search=alice-lq")
        .addHeader("X-Session-Id", sessionId)
        .responseBodyAs(Dtos.Page.class).invoke().body();
    assertThat(narrowSearch.data()).hasSize(1);

    // sort: username descending puts carol-lq before bob-lq before alice-lq among the matches.
    var sorted = httpClient.GET("/api/users?search=-lq&sort%5Bcolumn%5D=username&sort%5Bdirection%5D=desc")
        .addHeader("X-Session-Id", sessionId)
        .responseBodyAs(Dtos.Page.class).invoke().body();
    var usernames = ((List<Map<String, Object>>) sorted.data()).stream().map(u -> u.get("username")).toList();
    assertThat(usernames).containsExactly("carol-lq", "bob-lq", "alice-lq");

    // pagination: limit 1 page 2 of the same sorted, searched set returns exactly bob-lq, and
    // reports the total count across every page rather than just the one page returned.
    var paged = httpClient.GET("/api/users?search=-lq&sort%5Bcolumn%5D=username&sort%5Bdirection%5D=desc"
            + "&pagination%5Bpage%5D=2&pagination%5Blimit%5D=1")
        .addHeader("X-Session-Id", sessionId)
        .responseBodyAs(Dtos.Page.class).invoke().body();
    var pagedUsernames = ((List<Map<String, Object>>) paged.data()).stream().map(u -> u.get("username")).toList();
    assertThat(pagedUsernames).containsExactly("bob-lq");
    assertThat(paged.pagination().totalItems()).isEqualTo(3);
    assertThat(paged.pagination().totalPages()).isEqualTo(3);
    assertThat(paged.pagination().currentPage()).isEqualTo(2);
  }

  @Test
  void usersListFiltersByIsAdmin() {
    String sessionId = setupInitialAdmin();
    createUser(sessionId, "filtertarget-zz", "FilterTarget");

    // filters[isAdmin][0]=true keeps only admins — the seeded root user, not the just-created
    // non-admin — out of whatever else this shared TestKit instance has accumulated by now.
    var admins = eventually(
        () -> httpClient.GET("/api/users?search=root&filters%5BisAdmin%5D%5B0%5D=true")
            .addHeader("X-Session-Id", sessionId)
            .responseBodyAs(Dtos.Page.class).invoke().body(),
        p -> !p.data().isEmpty());
    assertThat(((List<Map<String, Object>>) admins.data()).stream().map(u -> u.get("username")).toList())
        .containsExactly("root");

    var nonAdmins = eventually(
        () -> httpClient.GET("/api/users?search=filtertarget-zz&filters%5BisAdmin%5D%5B0%5D=false")
            .addHeader("X-Session-Id", sessionId)
            .responseBodyAs(Dtos.Page.class).invoke().body(),
        p -> !p.data().isEmpty());
    assertThat(((List<Map<String, Object>>) nonAdmins.data()).stream().map(u -> u.get("username")).toList())
        .containsExactly("filtertarget-zz");

    var mismatched = httpClient.GET("/api/users?search=filtertarget-zz&filters%5BisAdmin%5D%5B0%5D=true")
        .addHeader("X-Session-Id", sessionId)
        .responseBodyAs(Dtos.Page.class).invoke().body();
    assertThat(mismatched.data()).isEmpty();
  }

  @Test
  void signupTokensStreamDeliversCurrentState() throws Exception {
    String sessionId = setupInitialAdmin();
    String frame = StreamingIntegrationTest.readFrameUntil(
        "http://localhost:" + testKit.getPort() + "/api/signup-tokens/stream", sessionId,
        f -> true, java.time.Duration.ofSeconds(10));
    assertThat(frame).isNotNull();
  }

  @Test
  void adminPasskeyCredentialsStreamDeliversTheEmptyCredentialListForAFreshUser() throws Exception {
    String sessionId = setupInitialAdmin();
    String frame = StreamingIntegrationTest.readFrameUntil(
        "http://localhost:" + testKit.getPort() + "/api/users/" + adminUserId + "/webauthn-credentials/stream",
        sessionId, f -> true, java.time.Duration.ofSeconds(10));
    assertThat(frame).isEqualTo("[]");
  }

  @Test
  void adminPasskeyCredentialsStreamRejectsANonAdminCaller() {
    String sessionId = setupInitialAdmin();
    createUser(sessionId, "notadmin-zz", "NotAdmin");
    var notAdmin = eventually(
        () -> httpClient.GET("/api/users?search=notadmin-zz").addHeader("X-Session-Id", sessionId)
            .responseBodyAs(Dtos.Page.class).invoke().body(),
        p -> !p.data().isEmpty());
    var notAdminId = ((Map<String, Object>) notAdmin.data().get(0)).get("id").toString();
    var notAdminSession = httpClient.POST("/login")
        .withRequestBody(new OidcEndpoint.LoginRequest(notAdminId))
        .responseBodyAs(OidcEndpoint.LoginResponse.class).invoke().body().session_id();

    var response = httpClient.GET("/api/users/" + adminUserId + "/webauthn-credentials/stream")
        .addHeader("X-Session-Id", notAdminSession)
        .invoke().httpResponse();
    assertThat(response.status().intValue()).isEqualTo(403);
  }
}
