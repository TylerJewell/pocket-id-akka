package io.akka.pocketid.application;

import akka.javasdk.annotations.Component;
import akka.javasdk.keyvalueentity.KeyValueEntity;
import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.jwk.KeyUse;
import com.nimbusds.jose.jwk.RSAKey;
import com.nimbusds.jose.jwk.gen.RSAKeyGenerator;
import java.text.ParseException;

/**
 * The persisted JWT signing key backing every ID token, access token, and the JWKS document
 * (SPEC-001 §3 rules 2, 11) — the entity form of `key_rotate.go`'s DB-backed key. Persisting it
 * here (rather than generating one fresh per process, as this port originally did) is what makes
 * {@code POST /api/admin/keys/rotate} (`OidcEndpoint`) a real rotation rather than a no-op: the
 * new key survives past the request that created it and is what the next token gets signed with,
 * including across a restart.
 *
 * <p>{@code privateJwkJson} is stored encrypted at rest (AES-256-GCM, {@link EncryptionSupport}),
 * matching the source's own {@code EncryptedString} treatment of the signing key
 * (`jwkutils.KeyProviderDatabase`). Every reply the entity itself hands back carries the
 * decrypted JSON — only the persisted {@code currentState()} is ciphertext.
 */
@Component(id = "signing-key")
public class SigningKeyEntity extends KeyValueEntity<SigningKeyEntity.State> {

  public record State(String keyId, String privateJwkJson, long rotatedAtMillis) {
    public boolean isEmpty() { return keyId == null; }
  }

  @Override
  public State emptyState() {
    return new State(null, null, 0);
  }

  /** Idempotent: returns the current key, generating and persisting one on first call only.
   * Safe under concurrent callers because a KeyValueEntity serializes its own commands. */
  public Effect<State> ensure(Long nowMillis) {
    if (!currentState().isEmpty()) return effects().reply(decrypted(currentState()));
    var plain = generate(nowMillis);
    var encrypted = new State(plain.keyId(), EncryptionSupport.encrypt(plain.privateJwkJson(), EncryptionSupport.currentMasterKey()), plain.rotatedAtMillis());
    return effects().updateState(encrypted).thenReply(plain);
  }

  /** Unconditionally replaces the active key — `pocket-id key-rotate`'s equivalent. Old tokens
   * signed with the previous key stop verifying immediately; the source recommends a restart of
   * every instance after rotating for the same reason (a new key must be what every replica signs
   * and verifies with), which this port's README's "Where it differs" list carries forward as the
   * single-process caveat this KeyValueEntity does not remove. */
  public Effect<State> rotate(Long nowMillis) {
    var plain = generate(nowMillis);
    var encrypted = new State(plain.keyId(), EncryptionSupport.encrypt(plain.privateJwkJson(), EncryptionSupport.currentMasterKey()), plain.rotatedAtMillis());
    return effects().updateState(encrypted).thenReply(plain);
  }

  public record ReencryptCmd(String oldMasterKey, String newMasterKey) {}

  /** `encryption-key-rotate`'s signing-key half: re-wraps the already-persisted key under a new
   * master key without changing the key itself (unlike {@link #rotate}, which mints a new key). */
  public Effect<String> reencrypt(ReencryptCmd cmd) {
    if (currentState().isEmpty()) return effects().reply("ok");
    var s = currentState();
    var next = new State(s.keyId(), EncryptionSupport.reencrypt(s.privateJwkJson(), cmd.oldMasterKey(), cmd.newMasterKey()), s.rotatedAtMillis());
    return effects().updateState(next).thenReply("ok");
  }

  private static State decrypted(State encrypted) {
    return new State(encrypted.keyId(), EncryptionSupport.decrypt(encrypted.privateJwkJson(), EncryptionSupport.currentMasterKey()), encrypted.rotatedAtMillis());
  }

  private static State generate(long nowMillis) {
    try {
      String kid = "pocket-id-akka-" + nowMillis;
      RSAKey key = new RSAKeyGenerator(2048).keyID(kid).keyUse(KeyUse.SIGNATURE).algorithm(JWSAlgorithm.RS256).generate();
      return new State(kid, key.toJSONString(), nowMillis);
    } catch (JOSEException e) {
      throw new IllegalStateException("failed to generate OIDC signing key", e);
    }
  }

  static RSAKey parse(State state) {
    try {
      return RSAKey.parse(state.privateJwkJson());
    } catch (ParseException e) {
      throw new IllegalStateException("failed to parse persisted signing key", e);
    }
  }
}
