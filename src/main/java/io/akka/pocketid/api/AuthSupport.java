package io.akka.pocketid.api;

import akka.http.javadsl.model.HttpHeader;
import akka.javasdk.client.ComponentClient;
import akka.javasdk.http.RequestContext;
import io.akka.pocketid.application.ApiKeysView;
import io.akka.pocketid.application.AuthnSessionEntity;
import io.akka.pocketid.application.SigningKeys;
import io.akka.pocketid.application.UserEntity;
import io.akka.pocketid.domain.User;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.time.Instant;

/**
 * middleware.go's {@code AuthMiddleware} — session cookie or bearer JWT first, then an API key,
 * exactly the fallback order the source uses (question-log-equivalent read of
 * internal/middleware/auth.go).
 */
public final class AuthSupport {
  private AuthSupport() {}

  public static User authenticatedUser(RequestContext ctx, ComponentClient cc) {
    String subject = sessionSubject(ctx, cc);
    if (subject == null) {
      subject = apiKeySubject(ctx, cc);
    }
    if (subject == null) return null;
    var user = cc.forKeyValueEntity(subject).method(UserEntity::get).invoke();
    return (user.id() == null || user.disabled()) ? null : user;
  }

  private static String sessionSubject(RequestContext ctx, ComponentClient cc) {
    String sessionId = ctx.requestHeader("X-Session-Id").map(HttpHeader::value).orElse(null);
    if (sessionId == null) {
      sessionId = ctx.requestHeader("Cookie").map(HttpHeader::value).map(AuthSupport::extractSessionCookie).orElse(null);
    }
    if (sessionId != null) {
      var session = cc.forKeyValueEntity(sessionId).method(AuthnSessionEntity::get).invoke();
      if (!session.isEmpty() && session.subject() != null) return session.subject();
    }
    String bearer = ctx.requestHeader("Authorization").map(HttpHeader::value).orElse(null);
    if (bearer != null && bearer.startsWith("Bearer ")) {
      var claims = SigningKeys.verify(cc, bearer.substring("Bearer ".length()));
      if (claims != null) {
        try {
          if (claims.getExpirationTime() != null && claims.getExpirationTime().after(new java.util.Date())) {
            return claims.getSubject();
          }
        } catch (Exception ignored) {
        }
      }
    }
    return null;
  }

  private static String apiKeySubject(RequestContext ctx, ComponentClient cc) {
    String raw = ctx.requestHeader("X-API-KEY").map(HttpHeader::value).orElse(null);
    if (raw == null) {
      String bearer = ctx.requestHeader("Authorization").map(HttpHeader::value).orElse(null);
      if (bearer != null && bearer.startsWith("Bearer ")) raw = bearer.substring("Bearer ".length());
    }
    if (raw == null) return null;
    String hashed = sha256(raw);
    var rows = cc.forView().method(ApiKeysView::byHashedKey).invoke(hashed).keys();
    if (rows.isEmpty()) return null;
    var key = rows.get(0);
    if (Instant.now().toEpochMilli() >= key.expiresAtMillis()) return null;
    return key.userId();
  }

  public static String extractSessionCookie(String cookieHeader) {
    for (String part : cookieHeader.split(";")) {
      String trimmed = part.trim();
      if (trimmed.startsWith(OidcEndpoint.SESSION_COOKIE + "=")) {
        return trimmed.substring((OidcEndpoint.SESSION_COOKIE + "=").length());
      }
    }
    return null;
  }

  public static String sha256(String value) {
    try {
      var digest = MessageDigest.getInstance("SHA-256");
      byte[] hash = digest.digest(value.getBytes(StandardCharsets.UTF_8));
      var sb = new StringBuilder();
      for (byte b : hash) sb.append(String.format("%02x", b));
      return sb.toString();
    } catch (NoSuchAlgorithmException e) {
      throw new IllegalStateException(e);
    }
  }
}
