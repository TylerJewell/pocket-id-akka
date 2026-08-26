package io.akka.pocketid.domain;

import java.util.List;

/** usersignup — an admin-issued token that lets someone self-register without open signup enabled. */
public record SignupToken(
    String id,
    String token,
    long expiresAtMillis,
    int usageLimit,
    int usageCount,
    List<String> userGroupIds,
    long createdAtMillis) {

  public boolean isUsable(long now) {
    return now < expiresAtMillis && usageCount < usageLimit;
  }

  public SignupToken consumed() {
    return new SignupToken(id, token, expiresAtMillis, usageLimit, usageCount + 1, userGroupIds, createdAtMillis);
  }
}
