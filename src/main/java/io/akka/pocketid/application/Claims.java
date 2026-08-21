package io.akka.pocketid.application;

import io.akka.pocketid.domain.SeededUser;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/** The scope-gated claim set — SPEC-001 §3 rule 13, question-log row 6. */
public final class Claims {

  private Claims() {}

  public static Map<String, Object> forScope(SeededUser user, List<String> scopes) {
    Map<String, Object> claims = new LinkedHashMap<>();
    claims.put("sub", user.subject());

    if (scopes.contains("profile")) {
      claims.put("given_name", user.givenName());
      claims.put("family_name", user.familyName());
      claims.put("name", user.givenName() + " " + user.familyName());
      claims.put("display_name", user.displayName());
      claims.put("preferred_username", user.preferredUsername());
    }

    if (scopes.contains("email") && user.email() != null && !user.email().isEmpty()) {
      claims.put("email", user.email());
      claims.put("email_verified", user.emailVerified());
    }

    if (scopes.contains("groups")) {
      claims.put("groups", user.groups());
    }

    return claims;
  }
}
