package io.akka.pocketid.domain;

import java.util.List;

/** model.go `UserGroup` — a group of users, usable to restrict OIDC client access and to fan out custom claims. */
public record UserGroup(
    String id,
    String name,
    String friendlyName,
    List<String> userIds,
    List<String> allowedOidcClientIds,
    long createdAtMillis,
    long updatedAtMillis) {}
