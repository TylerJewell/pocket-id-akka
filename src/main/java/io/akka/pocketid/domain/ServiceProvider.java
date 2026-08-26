package io.akka.pocketid.domain;

/** scimsync — a SCIM 2.0 endpoint this instance provisions users/groups into for one OIDC client. */
public record ServiceProvider(
    String id,
    String oidcClientId,
    String endpointUrl,
    String bearerToken,
    Long lastSyncedAtMillis,
    long createdAtMillis) {}
