package io.akka.pocketid.application;

import io.akka.pocketid.domain.OidcClient;
import io.akka.pocketid.domain.SeededUser;
import java.util.List;
import java.util.Map;

/**
 * The one client and one user this port seeds instead of exposing management APIs for —
 * SPEC-001 §1, §4.
 */
public final class SeedData {

  private SeedData() {}

  public static final OidcClient CLIENT =
      new OidcClient(
          "test-client",
          "test-secret",
          List.of("http://localhost:9034/callback", "https://oidcdebugger.com/debug"));

  public static final SeededUser USER =
      new SeededUser(
          "alice",
          "alice@example.com",
          true,
          "Alice",
          "Anderson",
          "Alice Anderson",
          "alice",
          List.of("everyone"));

  private static final Map<String, SeededUser> USERS_BY_SUBJECT = Map.of(USER.subject(), USER);

  public static OidcClient clientById(String clientId) {
    return CLIENT.clientId().equals(clientId) ? CLIENT : null;
  }

  public static SeededUser userBySubject(String subject) {
    return USERS_BY_SUBJECT.get(subject);
  }
}
