package io.akka.pocketid.api;

import akka.http.javadsl.model.HttpResponse;
import akka.http.javadsl.model.StatusCodes;
import akka.javasdk.annotations.Acl;
import akka.javasdk.annotations.http.Delete;
import akka.javasdk.annotations.http.Get;
import akka.javasdk.annotations.http.HttpEndpoint;
import akka.javasdk.annotations.http.Post;
import akka.javasdk.client.ComponentClient;
import akka.javasdk.http.AbstractHttpEndpoint;
import akka.javasdk.http.HttpResponses;
import io.akka.pocketid.application.AppConfigEntity;
import io.akka.pocketid.application.OneTimeAccessTokenEntity;
import io.akka.pocketid.application.SignupTokenEntity;
import io.akka.pocketid.application.SignupTokensView;
import io.akka.pocketid.application.UserEntity;
import io.akka.pocketid.application.UsersView;
import java.time.Instant;
import java.util.List;
import java.util.Map;
import java.util.UUID;

/** usersignup — public/token-gated self-signup, admin signup tokens, initial-admin setup wizard,
 * and the public one-time-access-token/email exchange (onetimeaccess.go's unauthenticated half). */
@Acl(allow = @Acl.Matcher(principal = Acl.Principal.ALL))
@HttpEndpoint("/api")
public class SignupEndpoint extends AbstractHttpEndpoint {

  private final ComponentClient cc;

  public SignupEndpoint(ComponentClient cc) { this.cc = cc; }

  private boolean isAdmin() {
    var u = AuthSupport.authenticatedUser(requestContext(), cc);
    return u != null && u.isAdmin();
  }

  // ---- initial-admin setup wizard --------------------------------------------------------

  @Get("/signup/setup")
  public HttpResponse setupStatus() {
    boolean anyUser = !cc.forView().method(UsersView::all).invoke().users().isEmpty();
    return HttpResponses.ok(Map.of("setupCompleted", anyUser));
  }

  public record SetupRequest(String username, String email, String firstName, String lastName) {}

  @Post("/signup/setup")
  public HttpResponse setup(SetupRequest body) {
    if (!cc.forView().method(UsersView::all).invoke().users().isEmpty()) {
      return HttpResponses.ok(Map.of("error", "Setup has already been completed.")).withStatus(StatusCodes.BAD_REQUEST);
    }
    String id = UUID.randomUUID().toString();
    long now = Instant.now().toEpochMilli();
    var user = cc.forKeyValueEntity(id).method(UserEntity::create).invoke(new UserEntity.Create(
        id, body.username(), body.email(), body.firstName(), body.lastName(), null, true, List.of(), now));
    AuditRecorder.record(cc, requestContext(), "ACCOUNT_CREATED", user.id(), user.username(), null);
    return SessionSupport.startSession(cc, user.id());
  }

  // ---- open / token-gated self-signup ----------------------------------------------------

  public record SignupRequest(String username, String email, String firstName, String lastName, String signupToken) {}

  @Post("/signup")
  public HttpResponse signup(SignupRequest body) {
    var config = cc.forKeyValueEntity("singleton").method(AppConfigEntity::get).invoke();
    boolean open = "open".equals(config.get("allowUserSignups"));
    SignupTokenEntity.class.getSimpleName(); // no-op, keeps import used if refactored
    List<String> groupIds = List.of();
    if (!open) {
      if (body.signupToken() == null) {
        return HttpResponses.ok(Map.of("error", "Open signup is disabled.")).withStatus(StatusCodes.FORBIDDEN);
      }
      var rows = cc.forView().method(SignupTokensView::byToken).invoke(body.signupToken()).tokens();
      if (rows.isEmpty() || !rows.get(0).isUsable(Instant.now().toEpochMilli())) {
        return HttpResponses.ok(Map.of("error", "Invalid or expired signup token.")).withStatus(StatusCodes.BAD_REQUEST);
      }
      cc.forKeyValueEntity(rows.get(0).id()).method(SignupTokenEntity::consume).invoke();
      groupIds = rows.get(0).userGroupIds();
    }
    String id = UUID.randomUUID().toString();
    long now = Instant.now().toEpochMilli();
    var user = cc.forKeyValueEntity(id).method(UserEntity::create).invoke(new UserEntity.Create(
        id, body.username(), body.email(), body.firstName(), body.lastName(), null, false, groupIds, now));
    AuditRecorder.record(cc, requestContext(), "ACCOUNT_CREATED", user.id(), user.username(), null);
    return SessionSupport.startSession(cc, user.id());
  }

  // ---- admin-managed signup tokens --------------------------------------------------------

  public record CreateSignupToken(long ttlSeconds, int usageLimit, List<String> userGroupIds) {}

  @Post("/signup-tokens")
  public HttpResponse createToken(CreateSignupToken body) {
    if (!isAdmin()) return HttpResponses.ok(Map.of("error", "forbidden")).withStatus(StatusCodes.FORBIDDEN);
    String id = UUID.randomUUID().toString();
    String token = UUID.randomUUID().toString().replace("-", "").substring(0, 12);
    long now = Instant.now().toEpochMilli();
    var t = cc.forKeyValueEntity(id).method(SignupTokenEntity::create).invoke(new SignupTokenEntity.Create(
        id, token, now + body.ttlSeconds() * 1000, body.usageLimit(), body.userGroupIds() == null ? List.of() : body.userGroupIds(), now));
    return HttpResponses.ok(t).withStatus(StatusCodes.CREATED);
  }

  @Get("/signup-tokens")
  public HttpResponse listTokens() {
    if (!isAdmin()) return HttpResponses.ok(Map.of("error", "forbidden")).withStatus(StatusCodes.FORBIDDEN);
    return HttpResponses.ok(Dtos.page(cc.forView().method(SignupTokensView::all).invoke().tokens()));
  }

  @Delete("/signup-tokens/{id}")
  public HttpResponse deleteToken(String id) {
    if (!isAdmin()) return HttpResponses.ok(Map.of("error", "forbidden")).withStatus(StatusCodes.FORBIDDEN);
    cc.forKeyValueEntity(id).method(SignupTokenEntity::delete).invoke();
    return HttpResponses.ok(Map.of("status", "deleted"));
  }

  // ---- public one-time-access exchange ----------------------------------------------------

  @Post("/one-time-access-token/{token}")
  public HttpResponse exchangeToken(String token) {
    var outcome = cc.forKeyValueEntity(token).method(OneTimeAccessTokenEntity::consume).invoke(Instant.now().toEpochMilli());
    if (outcome.result() != OneTimeAccessTokenEntity.ConsumeResult.OK) {
      return HttpResponses.ok(Map.of("error", "Invalid or expired token.")).withStatus(StatusCodes.BAD_REQUEST);
    }
    return SessionSupport.startSession(cc, outcome.userId());
  }

  public record OneTimeEmailRequest(String email, String redirectPath) {}

  @Post("/one-time-access-email")
  public HttpResponse requestOneTimeEmail(OneTimeEmailRequest body) {
    var config = cc.forKeyValueEntity("singleton").method(AppConfigEntity::get).invoke();
    if (!Boolean.parseBoolean(config.getOrDefault("emailOneTimeAccessAsUnauthenticatedEnabled", "false"))) {
      return HttpResponses.ok(Map.of("error", "This feature is disabled.")).withStatus(StatusCodes.FORBIDDEN);
    }
    var user = cc.forView().method(UsersView::byEmail).invoke(body.email()).users().stream().findFirst().orElse(null);
    // Anti-enumeration: the response is identical whether or not the email exists.
    if (user != null) {
      String token = io.akka.pocketid.api.OneTimeAccess.randomToken(15 * 60_000L);
      long expiresAt = Instant.now().toEpochMilli() + 15 * 60_000L;
      cc.forKeyValueEntity(token).method(OneTimeAccessTokenEntity::issue).invoke(new OneTimeAccessTokenEntity.Issue(token, user.id(), expiresAt));
    }
    return HttpResponses.ok(Map.of("status", "sent"));
  }
}
