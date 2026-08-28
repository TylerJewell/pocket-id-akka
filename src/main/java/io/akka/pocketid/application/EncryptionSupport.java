package io.akka.pocketid.application;

import java.security.GeneralSecurityException;
import java.security.SecureRandom;
import java.util.Base64;
import javax.crypto.Cipher;
import javax.crypto.Mac;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.SecretKeySpec;

/**
 * At-rest encryption for the two secrets the source keeps as {@code EncryptedString} columns —
 * the OIDC signing key's private JWK, and a SCIM service provider's bearer token
 * (`encrypted_string.go`, `crypto.go`). AES-256-GCM with a key derived by HKDF-SHA256 from a
 * caller-supplied master secret, mirroring the source's own derive-then-encrypt shape; the exact
 * bytes are not required to match since this is a fresh deployment with no existing ciphertext to
 * read, only the property that changing the master secret and re-encrypting (see
 * {@link #reencrypt}) is how {@code encryption-key-rotate} works.
 *
 * <p>The master secret comes from the {@code ENCRYPTION_KEY} environment variable. Unset falls
 * back to a fixed development key — every other optional secret in this codebase degrades the
 * same way (see {@link FileStorage}'s S3 credentials) rather than refusing to start; an operator
 * who cares about the at-rest guarantee sets a real one and never needs the fallback.
 */
public final class EncryptionSupport {
  private EncryptionSupport() {}

  private static final String HKDF_INFO = "pocketid-akka/encrypted_string";
  private static final String DEV_DEFAULT_KEY = "pocket-id-akka-dev-encryption-key-not-for-production";
  private static final SecureRandom RANDOM = new SecureRandom();

  public static String currentMasterKey() {
    String env = System.getenv("ENCRYPTION_KEY");
    return (env == null || env.isEmpty()) ? DEV_DEFAULT_KEY : env;
  }

  /** HKDF-SHA256, RFC 5869: extract then expand to a 32-byte AES-256 key. */
  private static byte[] deriveKey(String masterSecret) {
    try {
      Mac mac = Mac.getInstance("HmacSHA256");
      mac.init(new SecretKeySpec(new byte[32], "HmacSHA256")); // zero salt, matching the source's fixed-salt derivation
      byte[] prk = mac.doFinal(masterSecret.getBytes(java.nio.charset.StandardCharsets.UTF_8));

      mac.init(new SecretKeySpec(prk, "HmacSHA256"));
      mac.update(HKDF_INFO.getBytes(java.nio.charset.StandardCharsets.UTF_8));
      mac.update((byte) 1);
      return java.util.Arrays.copyOf(mac.doFinal(), 32);
    } catch (GeneralSecurityException e) {
      throw new IllegalStateException("failed to derive encryption key", e);
    }
  }

  public static String encrypt(String plaintext, String masterSecret) {
    if (plaintext == null) return null;
    try {
      byte[] nonce = new byte[12];
      RANDOM.nextBytes(nonce);
      Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
      cipher.init(Cipher.ENCRYPT_MODE, new SecretKeySpec(deriveKey(masterSecret), "AES"), new GCMParameterSpec(128, nonce));
      byte[] ciphertext = cipher.doFinal(plaintext.getBytes(java.nio.charset.StandardCharsets.UTF_8));
      byte[] out = new byte[nonce.length + ciphertext.length];
      System.arraycopy(nonce, 0, out, 0, nonce.length);
      System.arraycopy(ciphertext, 0, out, nonce.length, ciphertext.length);
      return Base64.getEncoder().encodeToString(out);
    } catch (GeneralSecurityException e) {
      throw new IllegalStateException("encryption failed", e);
    }
  }

  public static String decrypt(String encoded, String masterSecret) {
    if (encoded == null) return null;
    try {
      byte[] all = Base64.getDecoder().decode(encoded);
      byte[] nonce = java.util.Arrays.copyOfRange(all, 0, 12);
      byte[] ciphertext = java.util.Arrays.copyOfRange(all, 12, all.length);
      Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
      cipher.init(Cipher.DECRYPT_MODE, new SecretKeySpec(deriveKey(masterSecret), "AES"), new GCMParameterSpec(128, nonce));
      return new String(cipher.doFinal(ciphertext), java.nio.charset.StandardCharsets.UTF_8);
    } catch (GeneralSecurityException e) {
      throw new IllegalStateException("decryption failed — wrong key or corrupt ciphertext", e);
    }
  }

  /** `encryption-key-rotate`: decrypt with the outgoing key, encrypt with the incoming one. */
  public static String reencrypt(String encoded, String oldMasterSecret, String newMasterSecret) {
    if (encoded == null) return null;
    return encrypt(decrypt(encoded, oldMasterSecret), newMasterSecret);
  }
}
