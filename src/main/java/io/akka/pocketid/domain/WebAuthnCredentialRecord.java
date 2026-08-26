package io.akka.pocketid.domain;

/** model.go `WebauthnCredential` — a registered passkey. Public key stored as a COSE key (CBOR bytes, base64). */
public record WebAuthnCredentialRecord(
    String id,
    String userId,
    String name,
    String credentialIdBase64,
    String publicKeyCoseBase64,
    long signCount,
    long createdAtMillis) {

  public WebAuthnCredentialRecord withName(String name) {
    return new WebAuthnCredentialRecord(id, userId, name, credentialIdBase64, publicKeyCoseBase64, signCount, createdAtMillis);
  }

  public WebAuthnCredentialRecord withSignCount(long signCount) {
    return new WebAuthnCredentialRecord(id, userId, name, credentialIdBase64, publicKeyCoseBase64, signCount, createdAtMillis);
  }
}
