package io.akka.pocketid.api;

import akka.http.javadsl.model.HttpHeader;
import akka.http.javadsl.model.HttpResponse;
import akka.http.javadsl.model.StatusCodes;
import akka.javasdk.annotations.Acl;
import akka.javasdk.annotations.http.Delete;
import akka.javasdk.annotations.http.Get;
import akka.javasdk.annotations.http.HttpEndpoint;
import akka.javasdk.annotations.http.Patch;
import akka.javasdk.annotations.http.Post;
import akka.javasdk.client.ComponentClient;
import akka.javasdk.http.AbstractHttpEndpoint;
import akka.javasdk.http.HttpResponses;
import io.akka.pocketid.application.WebAuthnChallengeEntity;
import io.akka.pocketid.application.WebAuthnCredentialEntity;
import io.akka.pocketid.application.WebAuthnCredentialsView;
import io.akka.pocketid.application.WebAuthnSupport;
import java.time.Instant;
import java.util.List;
import java.util.Map;
import java.util.UUID;

/** webauthn — passkey registration and login. Real WebAuthn/FIDO2 verification via webauthn4j
 * (WebAuthnSupport), not a stand-in — the challenge is server-generated, held in
 * {@link WebAuthnChallengeEntity} for the ceremony's duration, and consumed exactly once. */
@Acl(allow = @Acl.Matcher(principal = Acl.Principal.ALL))
@HttpEndpoint("/api/webauthn")
public class WebAuthnEndpoint extends AbstractHttpEndpoint {

  private static final long CHALLENGE_TTL_MILLIS = 60_000;
  private final ComponentClient cc;

  public WebAuthnEndpoint(ComponentClient cc) { this.cc = cc; }

  public record CredentialCreationOptions(
      String challenge, String rpId, String rpName, String userId, long timeout) {}

  @Get("/register/start")
  public HttpResponse registerStart() {
    var u = AuthSupport.authenticatedUser(requestContext(), cc);
    if (u == null) return HttpResponses.ok(Map.of("error", "unauthorized")).withStatus(StatusCodes.UNAUTHORIZED);
    String sessionId = UUID.randomUUID().toString();
    String challenge = WebAuthnSupport.randomChallengeBase64();
    long expiresAt = Instant.now().toEpochMilli() + CHALLENGE_TTL_MILLIS;
    cc.forKeyValueEntity(sessionId).method(WebAuthnChallengeEntity::start)
        .invoke(new WebAuthnChallengeEntity.Start(sessionId, challenge, u.id(), true, expiresAt));
    return HttpResponses.ok(Map.of(
        "challengeSessionId", sessionId, "challenge", challenge, "rpId", WebAuthnSupport.RP_ID,
        "rpName", WebAuthnSupport.RP_NAME, "userId", u.id(), "timeout", CHALLENGE_TTL_MILLIS));
  }

  public record RegisterFinishRequest(String challengeSessionId, String name, String clientDataJSON, String attestationObject) {}

  @Post("/register/finish")
  public HttpResponse registerFinish(RegisterFinishRequest body) {
    var u = AuthSupport.authenticatedUser(requestContext(), cc);
    if (u == null) return HttpResponses.ok(Map.of("error", "unauthorized")).withStatus(StatusCodes.UNAUTHORIZED);
    var challengeState = cc.forKeyValueEntity(body.challengeSessionId()).method(WebAuthnChallengeEntity::get).invoke();
    if (challengeState.isEmpty() || Instant.now().toEpochMilli() >= challengeState.expiresAtMillis()) {
      return HttpResponses.ok(Map.of("error", "Registration ceremony expired or not found.")).withStatus(StatusCodes.BAD_REQUEST);
    }
    cc.forKeyValueEntity(body.challengeSessionId()).method(WebAuthnChallengeEntity::consume).invoke();
    try {
      var registered = WebAuthnSupport.verifyRegistration(body.clientDataJSON(), body.attestationObject(), challengeState.challengeBase64());
      String id = UUID.randomUUID().toString();
      var credential = cc.forKeyValueEntity(id).method(WebAuthnCredentialEntity::register).invoke(new WebAuthnCredentialEntity.Register(
          id, u.id(), body.name() == null || body.name().isEmpty() ? "New Passkey" : body.name(),
          registered.credentialIdBase64(), registered.publicKeyCoseBase64(), Instant.now().toEpochMilli()));
      AuditRecorder.record(cc, requestContext(), "PASSKEY_ADDED", u.id(), u.username(), null);
      return HttpResponses.ok(credential).withStatus(StatusCodes.CREATED);
    } catch (Exception e) {
      return HttpResponses.ok(Map.of("error", "Passkey registration failed: " + e.getMessage())).withStatus(StatusCodes.BAD_REQUEST);
    }
  }

  @Get("/login/start")
  public HttpResponse loginStart() {
    String sessionId = UUID.randomUUID().toString();
    String challenge = WebAuthnSupport.randomChallengeBase64();
    long expiresAt = Instant.now().toEpochMilli() + CHALLENGE_TTL_MILLIS;
    cc.forKeyValueEntity(sessionId).method(WebAuthnChallengeEntity::start)
        .invoke(new WebAuthnChallengeEntity.Start(sessionId, challenge, null, false, expiresAt));
    return HttpResponses.ok(Map.of("challengeSessionId", sessionId, "challenge", challenge, "rpId", WebAuthnSupport.RP_ID, "timeout", CHALLENGE_TTL_MILLIS));
  }

  public record LoginFinishRequest(
      String challengeSessionId, String credentialIdBase64, String clientDataJSON, String authenticatorData, String signature) {}

  @Post("/login/finish")
  public HttpResponse loginFinish(LoginFinishRequest body) {
    var challengeState = cc.forKeyValueEntity(body.challengeSessionId()).method(WebAuthnChallengeEntity::get).invoke();
    if (challengeState.isEmpty() || Instant.now().toEpochMilli() >= challengeState.expiresAtMillis()) {
      return HttpResponses.ok(Map.of("error", "Login ceremony expired or not found.")).withStatus(StatusCodes.BAD_REQUEST);
    }
    cc.forKeyValueEntity(body.challengeSessionId()).method(WebAuthnChallengeEntity::consume).invoke();

    var rows = cc.forView().method(WebAuthnCredentialsView::byCredentialId).invoke(body.credentialIdBase64()).credentials();
    if (rows.isEmpty()) return HttpResponses.ok(Map.of("error", "Unknown credential.")).withStatus(StatusCodes.BAD_REQUEST);
    var credential = rows.get(0);

    boolean ok = WebAuthnSupport.verifyAuthentication(
        credential.credentialIdBase64(), credential.publicKeyCoseBase64(), credential.signCount(),
        body.clientDataJSON(), body.authenticatorData(), body.signature(), challengeState.challengeBase64());
    if (!ok) return HttpResponses.ok(Map.of("error", "Passkey verification failed.")).withStatus(StatusCodes.UNAUTHORIZED);

    var user = cc.forKeyValueEntity(credential.userId()).method(io.akka.pocketid.application.UserEntity::get).invoke();
    AuditRecorder.record(cc, requestContext(), "SIGN_IN", user.id(), user.username(), null);
    return io.akka.pocketid.api.SessionSupport.startSession(cc, credential.userId());
  }

  @Post("/logout")
  public HttpResponse logout() {
    // The session cookie is client-held; logout simply asks the browser to drop it.
    return HttpResponses.ok(Map.of("status", "logged_out"))
        .addHeader(HttpHeader.parse("Set-Cookie", io.akka.pocketid.api.OidcEndpoint.SESSION_COOKIE + "=; Path=/; Max-Age=0; HttpOnly"));
  }

  @Get("/credentials")
  public HttpResponse listCredentials() {
    var u = AuthSupport.authenticatedUser(requestContext(), cc);
    if (u == null) return HttpResponses.ok(Map.of("error", "unauthorized")).withStatus(StatusCodes.UNAUTHORIZED);
    return HttpResponses.ok(cc.forView().method(WebAuthnCredentialsView::byUser).invoke(u.id()).credentials());
  }

  /** RENDERING.md R1 — the passkey-list screen subscribes to this instead of polling. */
  @Get("/credentials/stream")
  public HttpResponse streamCredentials() {
    var u = AuthSupport.authenticatedUser(requestContext(), cc);
    if (u == null) return HttpResponses.ok(Map.of("error", "unauthorized")).withStatus(StatusCodes.UNAUTHORIZED);
    return SseSupport.stream(
        () -> cc.forView().method(WebAuthnCredentialsView::byUser).invoke(u.id()).credentials());
  }

  @Delete("/credentials/{id}")
  public HttpResponse deleteCredential(String id) {
    var u = AuthSupport.authenticatedUser(requestContext(), cc);
    if (u == null) return HttpResponses.ok(Map.of("error", "unauthorized")).withStatus(StatusCodes.UNAUTHORIZED);
    var existing = cc.forKeyValueEntity(id).method(WebAuthnCredentialEntity::get).invoke();
    if (existing.id() == null || (!existing.userId().equals(u.id()) && !u.isAdmin())) {
      return HttpResponses.ok(Map.of("error", "forbidden")).withStatus(StatusCodes.FORBIDDEN);
    }
    cc.forKeyValueEntity(id).method(WebAuthnCredentialEntity::delete).invoke();
    AuditRecorder.record(cc, requestContext(), "PASSKEY_REMOVED", u.id(), u.username(), null);
    return HttpResponses.ok(Map.of("status", "deleted"));
  }

  public record RenameRequest(String name) {}

  @Patch("/credentials/{id}")
  public HttpResponse renameCredential(String id, RenameRequest body) {
    var u = AuthSupport.authenticatedUser(requestContext(), cc);
    if (u == null) return HttpResponses.ok(Map.of("error", "unauthorized")).withStatus(StatusCodes.UNAUTHORIZED);
    var existing = cc.forKeyValueEntity(id).method(WebAuthnCredentialEntity::get).invoke();
    if (existing.id() == null || !existing.userId().equals(u.id())) {
      return HttpResponses.ok(Map.of("error", "forbidden")).withStatus(StatusCodes.FORBIDDEN);
    }
    var updated = cc.forKeyValueEntity(id).method(WebAuthnCredentialEntity::rename).invoke(new WebAuthnCredentialEntity.Rename(body.name()));
    return HttpResponses.ok(updated);
  }

  public record ReauthRequest(String credentialIdBase64, String clientDataJSON, String authenticatorData, String signature, String challengeSessionId) {}

  /** Step-up re-authentication: proves the caller can still produce a passkey signature right
   * now, used before a sensitive operation. Reuses the login ceremony's verification. */
  @Post("/reauthenticate")
  public HttpResponse reauthenticate(ReauthRequest body) {
    var u = AuthSupport.authenticatedUser(requestContext(), cc);
    if (u == null) return HttpResponses.ok(Map.of("error", "unauthorized")).withStatus(StatusCodes.UNAUTHORIZED);
    var challengeState = cc.forKeyValueEntity(body.challengeSessionId()).method(WebAuthnChallengeEntity::get).invoke();
    if (challengeState.isEmpty()) return HttpResponses.ok(Map.of("error", "expired")).withStatus(StatusCodes.BAD_REQUEST);
    cc.forKeyValueEntity(body.challengeSessionId()).method(WebAuthnChallengeEntity::consume).invoke();
    var rows = cc.forView().method(WebAuthnCredentialsView::byUser).invoke(u.id()).credentials();
    var credential = rows.stream().filter(c -> c.credentialIdBase64().equals(body.credentialIdBase64())).findFirst().orElse(null);
    if (credential == null) return HttpResponses.ok(Map.of("error", "unknown credential")).withStatus(StatusCodes.BAD_REQUEST);
    boolean ok = WebAuthnSupport.verifyAuthentication(
        credential.credentialIdBase64(), credential.publicKeyCoseBase64(), credential.signCount(),
        body.clientDataJSON(), body.authenticatorData(), body.signature(), challengeState.challengeBase64());
    if (!ok) return HttpResponses.ok(Map.of("error", "verification failed")).withStatus(StatusCodes.UNAUTHORIZED);
    return HttpResponses.ok(Map.of("status", "reauthenticated", "amr", "phr"));
  }
}
