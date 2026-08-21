package io.akka.pocketid.domain;

import java.util.List;

/**
 * A seeded identity (SPEC-001 §1 — user management is out of scope; this port seeds one user
 * rather than provisioning through an API).
 */
public record SeededUser(
    String subject,
    String email,
    boolean emailVerified,
    String givenName,
    String familyName,
    String displayName,
    String preferredUsername,
    List<String> groups) {}
