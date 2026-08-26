package io.akka.pocketid.domain;

/** model.go `AuditLog` — an append-only record of a security-relevant event. */
public record AuditLogEntry(
    String id,
    String event, // SIGN_IN, TOKEN_SIGN_IN, ACCOUNT_CREATED, CLIENT_AUTHORIZATION,
    // NEW_CLIENT_AUTHORIZATION, DEVICE_CODE_AUTHORIZATION, NEW_DEVICE_CODE_AUTHORIZATION,
    // PASSKEY_ADDED, PASSKEY_REMOVED
    String userId,
    String username,
    String clientName,
    String ipAddress,
    String userAgent,
    long createdAtMillis) {}
