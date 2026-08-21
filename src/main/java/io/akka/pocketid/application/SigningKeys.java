package io.akka.pocketid.application;

import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.crypto.RSASSASigner;
import com.nimbusds.jose.crypto.RSASSAVerifier;
import com.nimbusds.jose.jwk.KeyUse;
import com.nimbusds.jose.jwk.RSAKey;
import com.nimbusds.jose.jwk.gen.RSAKeyGenerator;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import java.text.ParseException;

/**
 * The RS256 signing key backing every ID token, access token, and the JWKS document —
 * SPEC-001 §3 rules 2, 11. One key for the process lifetime; generated fresh on each start
 * rather than persisted, since nothing in this port's slice depends on a key surviving a
 * restart (question-log row 9 covers token lifetimes; key persistence was never a claim in
 * scope).
 */
public final class SigningKeys {

  private static final String KEY_ID = "pocket-id-akka-1";

  private static final RSAKey KEY_PAIR = generate();

  private SigningKeys() {}

  private static RSAKey generate() {
    try {
      return new RSAKeyGenerator(2048).keyID(KEY_ID).keyUse(KeyUse.SIGNATURE).algorithm(JWSAlgorithm.RS256).generate();
    } catch (JOSEException e) {
      throw new IllegalStateException("failed to generate OIDC signing key", e);
    }
  }

  /** The public half only — this is what {@code /.well-known/jwks.json} serves (rule 2). */
  public static RSAKey publicJwk() {
    return KEY_PAIR.toPublicJWK();
  }

  public static String sign(JWTClaimsSet claims) {
    try {
      var jwt = new SignedJWT(new JWSHeader.Builder(JWSAlgorithm.RS256).keyID(KEY_ID).build(), claims);
      jwt.sign(new RSASSASigner(KEY_PAIR));
      return jwt.serialize();
    } catch (JOSEException e) {
      throw new IllegalStateException("failed to sign token", e);
    }
  }

  public static JWTClaimsSet verify(String token) {
    try {
      var jwt = SignedJWT.parse(token);
      if (!jwt.verify(new RSASSAVerifier(KEY_PAIR))) return null;
      return jwt.getJWTClaimsSet();
    } catch (ParseException | JOSEException e) {
      return null;
    }
  }
}
