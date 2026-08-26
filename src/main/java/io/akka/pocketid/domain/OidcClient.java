package io.akka.pocketid.domain;

import java.util.List;

/**
 * A managed OAuth/OIDC client — model.go `OidcClient`. Extended from the OIDC-slice's seeded
 * record to a full CRUD-managed entity: name/description/logo for the admin UI, a client
 * secret (nullable for a public client), group restriction, and PKCE required for every client
 * (SPEC-001 §4's narrowing of the source's per-client policy, carried forward unchanged).
 */
public record OidcClient(
    String clientId,
    String name,
    String description,
    String clientSecret,
    boolean isPublic,
    List<String> redirectUris,
    List<String> postLogoutRedirectUris,
    boolean isGroupRestricted,
    List<String> allowedUserGroupIds,
    String logoDataUrl,
    long createdAtMillis,
    long updatedAtMillis) {

  public boolean hasRedirectUri(String uri) {
    return redirectUris.contains(uri);
  }

  public boolean hasPostLogoutRedirectUri(String uri) {
    return postLogoutRedirectUris.contains(uri);
  }

  public boolean userGroupAllowed(List<String> userGroupIds) {
    if (!isGroupRestricted) return true;
    return userGroupIds.stream().anyMatch(allowedUserGroupIds::contains);
  }
}
