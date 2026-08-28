package io.akka.pocketid.application;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import org.junit.jupiter.api.Test;

/** `encrypted_string.go`/`crypto.go`'s equivalent — AES-256-GCM round trip and the
 * decrypt-with-old/encrypt-with-new step `encryption-key-rotate` is built from. */
public class EncryptionSupportTest {

  @Test
  void encryptThenDecryptRoundTrips() {
    String ciphertext = EncryptionSupport.encrypt("super-secret-value", "key-a");
    assertThat(ciphertext).isNotEqualTo("super-secret-value");
    assertThat(EncryptionSupport.decrypt(ciphertext, "key-a")).isEqualTo("super-secret-value");
  }

  @Test
  void twoEncryptionsOfTheSameValueDifferByNonce() {
    String a = EncryptionSupport.encrypt("same-value", "key-a");
    String b = EncryptionSupport.encrypt("same-value", "key-a");
    assertThat(a).isNotEqualTo(b);
    assertThat(EncryptionSupport.decrypt(a, "key-a")).isEqualTo("same-value");
    assertThat(EncryptionSupport.decrypt(b, "key-a")).isEqualTo("same-value");
  }

  @Test
  void decryptingWithTheWrongKeyFails() {
    String ciphertext = EncryptionSupport.encrypt("super-secret-value", "key-a");
    assertThatThrownBy(() -> EncryptionSupport.decrypt(ciphertext, "key-b"))
        .isInstanceOf(IllegalStateException.class);
  }

  @Test
  void reencryptPreservesTheValueAcrossADifferentMasterKey() {
    String underOldKey = EncryptionSupport.encrypt("rotate-me", "old-master-key");
    String underNewKey = EncryptionSupport.reencrypt(underOldKey, "old-master-key", "new-master-key");

    assertThat(EncryptionSupport.decrypt(underNewKey, "new-master-key")).isEqualTo("rotate-me");
    assertThatThrownBy(() -> EncryptionSupport.decrypt(underNewKey, "old-master-key"))
        .isInstanceOf(IllegalStateException.class);
  }
}
