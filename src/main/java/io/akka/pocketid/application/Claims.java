package io.akka.pocketid.application;

import io.akka.pocketid.domain.CustomClaim;
import io.akka.pocketid.domain.User;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/** The scope-gated claim set — SPEC-001 §3 rule 13, question-log row 6, extended with the
 * custom-claim merge custom_claim_service.go applies to every issued token. */
public final class Claims {

  private Claims() {}

  public static Map<String, Object> forScope(User user, List<String> scopes, List<String> groupNames, List<CustomClaim> customClaims) {
    Map<String, Object> claims = new LinkedHashMap<>();
    claims.put("sub", user.id());

    if (scopes.contains("profile")) {
      claims.put("given_name", user.firstName());
      claims.put("family_name", user.lastName());
      claims.put("name", user.fullName());
      claims.put("display_name", user.displayName());
      claims.put("preferred_username", user.username());
    }

    if (scopes.contains("email") && user.email() != null && !user.email().isEmpty()) {
      claims.put("email", user.email());
      claims.put("email_verified", user.emailVerified());
    }

    if (scopes.contains("groups")) {
      claims.put("groups", groupNames);
    }

    // custom_claim_service.go: a user's own custom claims are merged in last, taking priority
    // over the same key from a group (source's documented precedence: user overrides group).
    if (customClaims != null) {
      for (var c : customClaims) {
        claims.put(c.key(), c.value());
      }
    }

    return claims;
  }
}
