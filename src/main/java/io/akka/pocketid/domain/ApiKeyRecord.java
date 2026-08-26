package io.akka.pocketid.domain;

/**
 * apikey/models.go `ApiKey` — a personal access token a user authenticates the HTTP API with
 * instead of a session. Bearer-auth alternative used by automation clients, not by browser sessions.
 */
public record ApiKeyRecord(
    String id,
    String name,
    String description,
    String hashedKey,
    String userId,
    long expiresAtMillis,
    Long lastUsedAtMillis,
    long createdAtMillis) {}
