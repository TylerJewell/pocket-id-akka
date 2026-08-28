package io.akka.pocketid.application;

import akka.javasdk.client.ComponentClient;
import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.crypto.RSASSASigner;
import com.nimbusds.jose.crypto.RSASSAVerifier;
import com.nimbusds.jose.jwk.RSAKey;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import java.text.ParseException;
import java.util.concurrent.atomic.AtomicReference;

/**
 * The RS256 signing key backing every ID token, access token, and the JWKS document —
 * SPEC-001 §3 rules 2, 11. Backed by {@link SigningKeyEntity} (persisted, rotatable) rather than
 * generated fresh per process; this class is a per-JVM cache in front of it so every sign/verify
 * call does not round-trip the entity. The cache is invalidated only by this same process calling
 * {@link #rotate}, matching the source's own key-rotate caveat that other running instances need a
 * restart to pick up a rotation performed elsewhere.
 */
public final class SigningKeys {

  private static final AtomicReference<SigningKeyEntity.State> CACHE = new AtomicReference<>();

  private SigningKeys() {}

  private static RSAKey current(ComponentClient cc) {
    var state = CACHE.updateAndGet(cur -> cur != null ? cur
        : cc.forKeyValueEntity("singleton").method(SigningKeyEntity::ensure).invoke(System.currentTimeMillis()));
    return SigningKeyEntity.parse(state);
  }

  /** The public half only — this is what {@code /.well-known/jwks.json} serves (rule 2). */
  public static RSAKey publicJwk(ComponentClient cc) {
    return current(cc).toPublicJWK();
  }

  public static String sign(ComponentClient cc, JWTClaimsSet claims) {
    try {
      var key = current(cc);
      var jwt = new SignedJWT(new JWSHeader.Builder(JWSAlgorithm.RS256).keyID(key.getKeyID()).build(), claims);
      jwt.sign(new RSASSASigner(key));
      return jwt.serialize();
    } catch (JOSEException e) {
      throw new IllegalStateException("failed to sign token", e);
    }
  }

  public static JWTClaimsSet verify(ComponentClient cc, String token) {
    try {
      var jwt = SignedJWT.parse(token);
      if (!jwt.verify(new RSASSAVerifier(current(cc)))) return null;
      return jwt.getJWTClaimsSet();
    } catch (ParseException | JOSEException e) {
      return null;
    }
  }

  /** `pocket-id key-rotate`'s equivalent: replaces the persisted key and this process's cache. */
  public static SigningKeyEntity.State rotate(ComponentClient cc) {
    var next = cc.forKeyValueEntity("singleton").method(SigningKeyEntity::rotate).invoke(System.currentTimeMillis());
    CACHE.set(next);
    return next;
  }
}
