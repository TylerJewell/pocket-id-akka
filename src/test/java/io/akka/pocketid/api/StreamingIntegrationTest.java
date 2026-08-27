package io.akka.pocketid.api;

import static org.assertj.core.api.Assertions.assertThat;

import akka.javasdk.testkit.TestKitSupport;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.time.Duration;
import java.util.List;
import org.junit.jupiter.api.Test;

/**
 * RENDERING.md R1 — every admin list screen subscribes to a stream instead of polling. A rule
 * nothing checks is a prediction of a fault (PIPELINE.md), so this drives the real stream
 * endpoints over real HTTP: content-type, a first frame with current state, and a second frame
 * once state actually changes underneath the subscription — the same guarantee the frontend's
 * {@code AdvancedTable.svelte} depends on to never poll.
 */
public class StreamingIntegrationTest extends TestKitSupport {

  // /signup/setup only succeeds once per running service — same caching pattern as
  // AdminSurfaceIntegrationTest, since this class's TestKit instance is shared across its tests.
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

  /** Reads Server-Sent-Event `data:` frames off a raw socket until one matches {@code until},
   * or gives up after {@code deadline}. The TestKit's own {@code httpClient} returns a single
   * parsed body, not a long-lived stream, so this uses the JDK's client directly against the
   * same {@code testKit.getPort()} the SDK client talks to. */
  private static String readFrameUntil(String path, String sessionId, java.util.function.Predicate<String> until, Duration deadline)
      throws Exception {
    // A tick that finds no change writes nothing to the response at all (SseSupport dedups), so
    // a genuinely broken endpoint would otherwise block this thread on the socket read forever.
    // Bounding the whole read (not just the between-reads check) with an executor deadline turns
    // that failure mode into a test failure instead of a hung build.
    var task = java.util.concurrent.Executors.newSingleThreadExecutor();
    try {
      return task.submit(() -> {
        var client = HttpClient.newHttpClient();
        var request = HttpRequest.newBuilder(URI.create(path))
            .header("X-Session-Id", sessionId)
            .header("Accept", "text/event-stream")
            .GET()
            .build();
        var response = client.sendAsync(request, HttpResponse.BodyHandlers.ofLines()).get();
        assertThat(response.statusCode()).isEqualTo(200);
        assertThat(response.headers().firstValue("Content-Type")).contains("text/event-stream");
        String last = null;
        try (var lines = response.body()) {
          var it = lines.iterator();
          while (it.hasNext()) {
            String line = it.next();
            if (!line.startsWith("data:")) continue;
            last = line.substring("data:".length()).trim();
            if (until.test(last)) return last;
          }
        }
        throw new AssertionError("stream closed with no matching frame; last frame was: " + last);
      }).get(deadline.toMillis(), java.util.concurrent.TimeUnit.MILLISECONDS);
    } finally {
      task.shutdownNow();
    }
  }

  @Test
  void usersStreamDeliversCurrentStateThenAnUpdateWhenAUserIsCreated() throws Exception {
    String sessionId = setupInitialAdmin();
    String base = "http://localhost:" + testKit.getPort();

    // The view backing this stream updates asynchronously from the entity signup/setup just
    // wrote, so — same as any other view read in this codebase — the very first tick can still
    // show the pre-update (empty) state. Unlike a fetch-once REST call, the stream self-heals:
    // a later tick is a fresh read, with no client-side retry needed.
    readFrameUntil(base + "/api/users/stream", sessionId, frame -> frame.contains("\"root\""), Duration.ofSeconds(10));

    httpClient.POST("/api/users")
        .addHeader("X-Session-Id", sessionId)
        .withRequestBody(new UserEndpoint.UpsertUser(
            "dana", "dana@example.com", true, "Dana", "Dev", "Dana Dev", false, "en", false, List.of()))
        .responseBodyAs(Dtos.UserDto.class).invoke().body();

    // A frame after the create reflects the new user without the client ever re-fetching.
    readFrameUntil(base + "/api/users/stream", sessionId, frame -> frame.contains("\"dana\""), Duration.ofSeconds(10));
  }

  @Test
  void streamEndpointsRejectAnUnauthenticatedCaller() {
    var response = httpClient.GET("/api/users/stream").invoke().httpResponse();
    assertThat(response.status().intValue()).isEqualTo(401);
  }
}
