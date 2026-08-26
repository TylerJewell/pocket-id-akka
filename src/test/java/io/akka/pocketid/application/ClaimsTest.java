package io.akka.pocketid.application;

import static org.assertj.core.api.Assertions.assertThat;

import io.akka.pocketid.domain.CustomClaim;
import io.akka.pocketid.domain.User;
import java.util.List;
import org.junit.jupiter.api.Test;

/** SPEC-001 §3 rule 13, question-log row 6 — scope gates exactly this claim set. */
public class ClaimsTest {

  private static final User USER =
      new User("u1", "pref", "u@example.com", true, "Given", "Family", "Given Family", false, null, false, null, List.of("g1", "g2"), 0, 0);

  @Test
  void noScopesYieldsOnlySubject() {
    var claims = Claims.forScope(USER, List.of(), List.of("g1", "g2"), List.of());
    assertThat(claims.keySet()).containsExactly("sub");
  }

  @Test
  void profileScopeAddsProfileClaimsOnly() {
    var claims = Claims.forScope(USER, List.of("profile"), List.of("g1", "g2"), List.of());
    assertThat(claims).containsEntry("given_name", "Given");
    assertThat(claims).containsEntry("family_name", "Family");
    assertThat(claims).containsEntry("display_name", "Given Family");
    assertThat(claims).containsEntry("preferred_username", "pref");
    assertThat(claims).doesNotContainKey("email");
    assertThat(claims).doesNotContainKey("groups");
  }

  @Test
  void emailScopeOmitsEmailVerifiedWhenEmailIsAbsent() {
    var noEmailUser = new User("u2", "p", null, false, "G", "F", "GF", false, null, false, null, List.of(), 0, 0);
    var claims = Claims.forScope(noEmailUser, List.of("email"), List.of(), List.of());
    assertThat(claims).doesNotContainKey("email");
    assertThat(claims).doesNotContainKey("email_verified");
  }

  @Test
  void emailScopeIncludesVerifiedFlagWhenEmailPresent() {
    var claims = Claims.forScope(USER, List.of("email"), List.of("g1", "g2"), List.of());
    assertThat(claims).containsEntry("email", "u@example.com");
    assertThat(claims).containsEntry("email_verified", true);
  }

  @Test
  void groupsScopeAddsGroupList() {
    var claims = Claims.forScope(USER, List.of("groups"), List.of("g1", "g2"), List.of());
    assertThat(claims).containsEntry("groups", List.of("g1", "g2"));
  }

  @Test
  void customClaimsAreMergedIn() {
    var claims = Claims.forScope(USER, List.of(), List.of(), List.of(new CustomClaim("department", "engineering")));
    assertThat(claims).containsEntry("department", "engineering");
  }
}
