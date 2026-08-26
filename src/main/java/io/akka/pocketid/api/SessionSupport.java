package io.akka.pocketid.api;

import akka.http.javadsl.model.HttpHeader;
import akka.javasdk.client.ComponentClient;
import akka.javasdk.http.HttpResponses;
import io.akka.pocketid.application.AuthnSessionEntity;
import java.time.Instant;
import java.util.UUID;

/** Mints a session and the cookie that carries it — shared by every flow that authenticates a
 * user outside the OIDC protocol surface itself (signup, setup, one-time-access exchange). */
public final class SessionSupport {
  private SessionSupport() {}

  public static akka.http.javadsl.model.HttpResponse startSession(ComponentClient cc, String subject) {
    String sessionId = UUID.randomUUID().toString();
    cc.forKeyValueEntity(sessionId).method(AuthnSessionEntity::create)
        .invoke(new AuthnSessionEntity.Create(sessionId, subject, Instant.now().toEpochMilli()));
    return HttpResponses.ok(new OidcEndpoint.LoginResponse(sessionId, subject))
        .addHeader(HttpHeader.parse("Set-Cookie", OidcEndpoint.SESSION_COOKIE + "=" + sessionId + "; Path=/; HttpOnly"));
  }
}
