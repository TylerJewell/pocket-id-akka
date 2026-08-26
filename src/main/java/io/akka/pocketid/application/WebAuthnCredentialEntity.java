package io.akka.pocketid.application;

import akka.javasdk.annotations.Component;
import akka.javasdk.keyvalueentity.KeyValueEntity;
import io.akka.pocketid.domain.WebAuthnCredentialRecord;

/** webauthn — one registered passkey, keyed by its own id. Looked up for login by the
 * credential id it carries, resolved through {@code WebAuthnCredentialsView}. */
@Component(id = "webauthn-credential")
public class WebAuthnCredentialEntity extends KeyValueEntity<WebAuthnCredentialRecord> {

  public record Register(String id, String userId, String name, String credentialIdBase64, String publicKeyCoseBase64, long nowMillis) {}

  public record UpdateSignCount(long signCount) {}

  public record Rename(String name) {}

  @Override
  public WebAuthnCredentialRecord emptyState() {
    return new WebAuthnCredentialRecord(null, null, null, null, null, 0, 0);
  }

  public Effect<WebAuthnCredentialRecord> register(Register cmd) {
    var rec = new WebAuthnCredentialRecord(cmd.id(), cmd.userId(), cmd.name(), cmd.credentialIdBase64(), cmd.publicKeyCoseBase64(), 0, cmd.nowMillis());
    return effects().updateState(rec).thenReply(rec);
  }

  public Effect<WebAuthnCredentialRecord> updateSignCount(UpdateSignCount cmd) {
    return effects().updateState(currentState().withSignCount(cmd.signCount())).thenReply(currentState().withSignCount(cmd.signCount()));
  }

  public Effect<WebAuthnCredentialRecord> rename(Rename cmd) {
    var updated = currentState().withName(cmd.name());
    return effects().updateState(updated).thenReply(updated);
  }

  public Effect<WebAuthnCredentialRecord> get() {
    return effects().reply(currentState());
  }

  public Effect<String> delete() {
    return effects().deleteEntity().thenReply("ok");
  }
}
