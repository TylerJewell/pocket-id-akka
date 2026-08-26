package io.akka.pocketid.domain;

import java.util.List;

/** A managed user account — model.go `User`. Replaces the fixed `SeededUser` the OIDC-only slice used. */
public record User(
    String id,
    String username,
    String email,
    boolean emailVerified,
    String firstName,
    String lastName,
    String displayName,
    boolean isAdmin,
    String locale,
    boolean disabled,
    String ldapId,
    List<String> groupIds,
    long createdAtMillis,
    long updatedAtMillis) {

  public String fullName() {
    String n = (firstName + " " + lastName).trim();
    if (!n.isEmpty()) return n;
    if (displayName != null && !displayName.isEmpty()) return displayName;
    return username;
  }

  public User withProfile(String username, String email, String firstName, String lastName, String displayName, String locale, long now) {
    return new User(id, username, email, emailVerified, firstName, lastName, displayName, isAdmin, locale, disabled, ldapId, groupIds, createdAtMillis, now);
  }

  public User withGroups(List<String> groupIds, long now) {
    return new User(id, username, email, emailVerified, firstName, lastName, displayName, isAdmin, locale, disabled, ldapId, groupIds, createdAtMillis, now);
  }

  public User withEmailVerified(boolean verified, long now) {
    return new User(id, username, email, verified, firstName, lastName, displayName, isAdmin, locale, disabled, ldapId, groupIds, createdAtMillis, now);
  }

  public User withDisabled(boolean disabled, long now) {
    return new User(id, username, email, emailVerified, firstName, lastName, displayName, isAdmin, locale, disabled, ldapId, groupIds, createdAtMillis, now);
  }

  public User withAdmin(boolean isAdmin, long now) {
    return new User(id, username, email, emailVerified, firstName, lastName, displayName, isAdmin, locale, disabled, ldapId, groupIds, createdAtMillis, now);
  }
}
