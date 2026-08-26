package io.akka.pocketid.application;

import com.webauthn4j.WebAuthnManager;
import com.webauthn4j.data.AuthenticationParameters;
import com.webauthn4j.data.AuthenticationRequest;
import com.webauthn4j.data.RegistrationParameters;
import com.webauthn4j.data.RegistrationRequest;
import com.webauthn4j.data.client.Origin;
import com.webauthn4j.data.client.challenge.Challenge;
import com.webauthn4j.data.client.challenge.DefaultChallenge;
import com.webauthn4j.server.ServerProperty;
import com.webauthn4j.util.Base64UrlUtil;
import java.security.SecureRandom;
import java.util.Base64;

/**
 * webauthn — the passkey register/login cryptographic ceremony, backed by webauthn4j (the same
 * kind of "don't hand-roll it" call the source makes with go-webauthn). Reduced from the source:
 * attestation is verified as "none"/self only (no AAGUID/MDS trust-chain lookup), and the
 * user-verification/authenticator-attachment policy knobs in app config are read but not
 * enforced at the cryptographic layer — SPEC-001 B-1 scope note.
 */
public final class WebAuthnSupport {
  private WebAuthnSupport() {}

  public static final String RP_ID = "localhost";
  public static final String RP_NAME = "Pocket ID";
  public static final String ORIGIN = "http://localhost:9127";

  private static final SecureRandom RANDOM = new SecureRandom();
  private static final WebAuthnManager MANAGER = WebAuthnManager.createNonStrictWebAuthnManager();

  public static String randomChallengeBase64() {
    byte[] b = new byte[32];
    RANDOM.nextBytes(b);
    return Base64.getUrlEncoder().withoutPadding().encodeToString(b);
  }

  public record RegisteredCredential(String credentialIdBase64, String publicKeyCoseBase64) {}

  public static RegisteredCredential verifyRegistration(
      String clientDataJsonBase64, String attestationObjectBase64, String challengeBase64) {
    byte[] clientDataJson = Base64UrlUtil.decode(clientDataJsonBase64);
    byte[] attestationObject = Base64UrlUtil.decode(attestationObjectBase64);
    Challenge challenge = new DefaultChallenge(Base64UrlUtil.decode(challengeBase64));
    ServerProperty serverProperty = new ServerProperty(new Origin(ORIGIN), RP_ID, challenge);

    var request = new RegistrationRequest(attestationObject, clientDataJson);
    var parameters = new RegistrationParameters(serverProperty, null, true, true);
    var data = MANAGER.verify(request, parameters);
    var attestedCredentialData = data.getAttestationObject().getAuthenticatorData().getAttestedCredentialData();
    byte[] credentialId = attestedCredentialData.getCredentialId();
    byte[] publicKeyCose = new com.webauthn4j.converter.util.ObjectConverter().getCborConverter().writeValueAsBytes(attestedCredentialData.getCOSEKey());
    return new RegisteredCredential(
        Base64UrlUtil.encodeToString(credentialId), Base64.getEncoder().encodeToString(publicKeyCose));
  }

  public static boolean verifyAuthentication(
      String credentialIdBase64, String publicKeyCoseBase64, long storedSignCount,
      String clientDataJsonBase64, String authenticatorDataBase64, String signatureBase64, String challengeBase64) {
    try {
      byte[] credentialId = Base64UrlUtil.decode(credentialIdBase64);
      byte[] publicKeyCose = Base64.getDecoder().decode(publicKeyCoseBase64);
      var authenticator = new com.webauthn4j.authenticator.AuthenticatorImpl(
          new com.webauthn4j.data.attestation.authenticator.AttestedCredentialData(
              new com.webauthn4j.data.attestation.authenticator.AAGUID(new byte[16]),
              credentialId,
              decodeCoseKey(publicKeyCose)),
          null, storedSignCount);

      Challenge challenge = new DefaultChallenge(Base64UrlUtil.decode(challengeBase64));
      ServerProperty serverProperty = new ServerProperty(new Origin(ORIGIN), RP_ID, challenge);

      var request = new AuthenticationRequest(
          credentialId, Base64UrlUtil.decode(authenticatorDataBase64), Base64UrlUtil.decode(clientDataJsonBase64), Base64UrlUtil.decode(signatureBase64));
      var parameters = new AuthenticationParameters(serverProperty, authenticator, null, true, true);
      MANAGER.verify(request, parameters);
      return true;
    } catch (Exception e) {
      return false;
    }
  }

  private static com.webauthn4j.data.attestation.authenticator.COSEKey decodeCoseKey(byte[] cose) {
    return new com.webauthn4j.converter.util.ObjectConverter().getCborConverter().readValue(cose, com.webauthn4j.data.attestation.authenticator.COSEKey.class);
  }
}
