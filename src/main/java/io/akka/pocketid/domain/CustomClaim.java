package io.akka.pocketid.domain;

/** custom_claim.go — a key/value pair attached to a user or a user group, merged into ID-token/userinfo claims. */
public record CustomClaim(String key, String value) {}
