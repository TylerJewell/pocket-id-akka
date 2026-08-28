package io.akka.pocketid.api;

import akka.http.javadsl.model.HttpResponse;
import akka.http.javadsl.model.StatusCodes;
import akka.javasdk.annotations.Acl;
import akka.javasdk.annotations.http.HttpEndpoint;
import akka.javasdk.annotations.http.Post;
import akka.javasdk.client.ComponentClient;
import akka.javasdk.http.AbstractHttpEndpoint;
import akka.javasdk.http.HttpResponses;
import io.akka.pocketid.application.DeviceLoginEntity;
import java.security.SecureRandom;
import java.time.Instant;
import java.util.Map;

/** devicelogin — the source's own browser-to-browser handoff ("login with another device"),
 * distinct from the RFC 8628 client grant OidcEndpoint implements. */
@Acl(allow = @Acl.Matcher(principal = Acl.Principal.ALL))
@HttpEndpoint("/api/device-login")
public class DeviceLoginEndpoint extends AbstractHttpEndpoint {

  private static final long TTL_MILLIS = 5 * 60_000;
  private static final SecureRandom RANDOM = new SecureRandom();
  private final ComponentClient cc;

  public DeviceLoginEndpoint(ComponentClient cc) { this.cc = cc; }

  @Post("/requests")
  public HttpResponse createRequest() {
    var limited = RateLimitSupport.check(cc, requestContext(), "device-login-create");
    if (limited != null) return limited;
    String code = randomCode();
    long expiresAt = Instant.now().toEpochMilli() + TTL_MILLIS;
    cc.forKeyValueEntity(code).method(DeviceLoginEntity::create).invoke(new DeviceLoginEntity.Create(code, expiresAt));
    return HttpResponses.ok(Map.of("code", code, "expiresIn", TTL_MILLIS / 1000));
  }

  @Post("/requests/{code}/exchange")
  public HttpResponse exchange(String code) {
    var limited = RateLimitSupport.check(cc, requestContext(), "device-login-exchange");
    if (limited != null) return limited;
    var state = cc.forKeyValueEntity(code).method(DeviceLoginEntity::get).invoke();
    if (state.isEmpty()) return HttpResponses.ok(Map.of("status", "not_found")).withStatus(StatusCodes.NOT_FOUND);
    if (Instant.now().toEpochMilli() >= state.expiresAtMillis()) {
      return HttpResponses.ok(Map.of("status", "expired"));
    }
    return switch (state.status()) {
      case PENDING -> HttpResponses.ok(Map.of("status", "pending"));
      case DENIED -> HttpResponses.ok(Map.of("status", "denied"));
      case CONSUMED -> HttpResponses.ok(Map.of("status", "already_consumed"));
      case APPROVED -> {
        cc.forKeyValueEntity(code).method(DeviceLoginEntity::consume).invoke();
        yield SessionSupport.startSession(cc, state.subject());
      }
    };
  }

  public record VerificationRequest(String code) {}

  @Post("/verification")
  public HttpResponse verification(VerificationRequest body) {
    var limited = RateLimitSupport.check(cc, requestContext(), "device-login-verification");
    if (limited != null) return limited;
    var u = AuthSupport.authenticatedUser(requestContext(), cc);
    if (u == null) return HttpResponses.ok(Map.of("error", "unauthorized")).withStatus(StatusCodes.UNAUTHORIZED);
    var state = cc.forKeyValueEntity(body.code()).method(DeviceLoginEntity::get).invoke();
    if (state.isEmpty()) return HttpResponses.ok(Map.of("error", "not found")).withStatus(StatusCodes.NOT_FOUND);
    return HttpResponses.ok(Map.of("status", state.status().name()));
  }

  public record DecisionRequest(String code, boolean decision) {}

  @Post("/verification/decision")
  public HttpResponse decide(DecisionRequest body) {
    var u = AuthSupport.authenticatedUser(requestContext(), cc);
    if (u == null) return HttpResponses.ok(Map.of("error", "unauthorized")).withStatus(StatusCodes.UNAUTHORIZED);
    var updated = cc.forKeyValueEntity(body.code()).method(DeviceLoginEntity::decide)
        .invoke(new DeviceLoginEntity.Decide(body.decision(), u.id()));
    return HttpResponses.ok(Map.of("status", updated.status().name()));
  }

  private String randomCode() {
    String alphabet = "BCDFGHJKLMNPQRSTVWXYZ23456789";
    StringBuilder sb = new StringBuilder("P");
    for (int i = 0; i < 7; i++) sb.append(alphabet.charAt(RANDOM.nextInt(alphabet.length())));
    return sb.toString();
  }
}
