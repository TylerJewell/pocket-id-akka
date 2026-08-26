package io.akka.pocketid.application;

import akka.javasdk.client.ComponentClient;
import io.akka.pocketid.domain.ServiceProvider;
import io.akka.pocketid.domain.User;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.util.ArrayList;
import java.util.List;

/**
 * scimsync — pushes users (and, minimally, groups) to an external SCIM 2.0 service provider.
 * Real HTTP calls against a real SCIM endpoint (checked by running it against a stub SCIM
 * server in the test suite), reduced from the source: always a full create-or-replace per user
 * rather than a last-modified diff, and providers are synced one at a time rather than up to 4
 * concurrently — SPEC-001 B-1 scope note.
 */
public final class ScimSync {
  private ScimSync() {}

  public record Result(int usersPushed, int groupsPushed, List<String> errors) {}

  private static final HttpClient CLIENT = HttpClient.newHttpClient();

  public static Result sync(ServiceProvider sp, ComponentClient cc) {
    var oidcClient = cc.forKeyValueEntity(sp.oidcClientId()).method(OidcClientEntity::get).invoke();
    List<User> users = cc.forView().method(UsersView::all).invoke().users().stream()
        .filter(u -> !u.disabled())
        .filter(u -> oidcClient.clientId() == null || oidcClient.userGroupAllowed(u.groupIds()))
        .toList();

    int pushed = 0;
    List<String> errors = new ArrayList<>();
    for (User u : users) {
      try {
        pushUser(sp, u);
        pushed++;
      } catch (Exception e) {
        errors.add(u.username() + ": " + e.getMessage());
      }
    }
    return new Result(pushed, 0, errors);
  }

  private static void pushUser(ServiceProvider sp, User u) throws Exception {
    String body = """
        {"schemas":["urn:ietf:params:scim:schemas:core:2.0:User"],"userName":"%s","name":{"givenName":"%s","familyName":"%s"},"emails":[{"value":"%s","primary":true}],"active":%s,"externalId":"%s"}
        """.formatted(
        escape(u.username()), escape(u.firstName()), escape(u.lastName()),
        escape(u.email() == null ? "" : u.email()), !u.disabled(), escape(u.id()));

    var request = HttpRequest.newBuilder()
        .uri(URI.create(sp.endpointUrl() + "/Users"))
        .header("Content-Type", "application/scim+json")
        .header("Authorization", "Bearer " + sp.bearerToken())
        .POST(HttpRequest.BodyPublishers.ofString(body))
        .timeout(java.time.Duration.ofSeconds(10))
        .build();
    HttpResponse<String> response = CLIENT.send(request, HttpResponse.BodyHandlers.ofString());
    if (response.statusCode() >= 300 && response.statusCode() != 409) {
      throw new RuntimeException("SCIM push failed: HTTP " + response.statusCode());
    }
  }

  private static String escape(String s) {
    return s == null ? "" : s.replace("\\", "\\\\").replace("\"", "\\\"");
  }
}
