package io.akka.pocketid.application;

import static org.assertj.core.api.Assertions.assertThat;

import io.akka.pocketid.domain.SeededUser;
import java.util.List;
import org.junit.jupiter.api.Test;

/** SPEC-001 §3 rule 13, question-log row 6 — scope gates exactly this claim set. */
public class ClaimsTest {

  private static final SeededUser USER =
      new SeededUser("u1", "u@example.com", true, "Given", "Family", "Given Family", "pref", List.of("g1", "g2"));

  @Test
  void noScopesYieldsOnlySubject() {
    var claims = Claims.forScope(USER, List.of());
    assertThat(claims.keySet()).containsExactly("sub");
  }

  @Test
  void profileScopeAddsProfileClaimsOnly() {
    var claims = Claims.forScope(USER, List.of("profile"));
    assertThat(claims).containsEntry("given_name", "Given");
    assertThat(claims).containsEntry("family_name", "Family");
    assertThat(claims).containsEntry("display_name", "Given Family");
    assertThat(claims).containsEntry("preferred_username", "pref");
    assertThat(claims).doesNotContainKey("email");
    assertThat(claims).doesNotContainKey("groups");
  }

  @Test
  void emailScopeOmitsEmailVerifiedWhenEmailIsAbsent() {
    var noEmailUser = new SeededUser("u2", null, false, "G", "F", "GF", "p", List.of());
    var claims = Claims.forScope(noEmailUser, List.of("email"));
    assertThat(claims).doesNotContainKey("email");
    assertThat(claims).doesNotContainKey("email_verified");
  }

  @Test
  void emailScopeIncludesVerifiedFlagWhenEmailPresent() {
    var claims = Claims.forScope(USER, List.of("email"));
    assertThat(claims).containsEntry("email", "u@example.com");
    assertThat(claims).containsEntry("email_verified", true);
  }

  @Test
  void groupsScopeAddsGroupList() {
    var claims = Claims.forScope(USER, List.of("groups"));
    assertThat(claims).containsEntry("groups", List.of("g1", "g2"));
  }
}
