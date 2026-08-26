package io.akka.pocketid.api;

import akka.http.javadsl.model.ContentType;
import akka.http.javadsl.model.ContentTypes;
import akka.http.javadsl.model.HttpResponse;
import akka.http.javadsl.model.MediaTypes;
import akka.http.javadsl.model.StatusCodes;
import akka.javasdk.annotations.Acl;
import akka.javasdk.annotations.http.Delete;
import akka.javasdk.annotations.http.Get;
import akka.javasdk.annotations.http.HttpEndpoint;
import akka.javasdk.annotations.http.Post;
import akka.javasdk.annotations.http.Put;
import akka.javasdk.client.ComponentClient;
import akka.javasdk.http.AbstractHttpEndpoint;
import akka.javasdk.http.HttpResponses;
import akka.util.ByteString;
import io.akka.pocketid.application.BlobEntity;
import io.akka.pocketid.application.CustomClaimSetEntity;
import io.akka.pocketid.application.EmailVerificationEntity;
import io.akka.pocketid.application.OneTimeAccessTokenEntity;
import io.akka.pocketid.application.UserEntity;
import io.akka.pocketid.application.UserGroupEntity;
import io.akka.pocketid.application.UserGroupsView;
import io.akka.pocketid.application.UsersView;
import io.akka.pocketid.domain.User;
import java.time.Instant;
import java.util.Base64;
import java.util.List;
import java.util.UUID;

/** user_controller.go — user CRUD, self-service profile, groups, profile pictures,
 * admin-issued one-time access, and self-service email verification. */
@Acl(allow = @Acl.Matcher(principal = Acl.Principal.ALL))
@HttpEndpoint("/api")
public class UserEndpoint extends AbstractHttpEndpoint {

  private final ComponentClient cc;

  public UserEndpoint(ComponentClient cc) {
    this.cc = cc;
  }

  private User me() { return AuthSupport.authenticatedUser(requestContext(), cc); }

  private HttpResponse requireAdmin() {
    var u = me();
    if (u == null) return HttpResponses.ok(err("unauthorized")).withStatus(StatusCodes.UNAUTHORIZED);
    if (!u.isAdmin()) return HttpResponses.ok(err("forbidden")).withStatus(StatusCodes.FORBIDDEN);
    return null;
  }

  private java.util.Map<String, String> err(String msg) { return java.util.Map.of("error", msg); }

  private Dtos.UserDto toDto(User u) {
    // Read each of the user's own groups directly from its entity rather than through
    // UserGroupsView: a group created in the same request as this user (POST /users with
    // userGroupIds) may not have reached the view's eventually-consistent projection yet.
    var groups = u.groupIds().stream()
        .map(gid -> cc.forKeyValueEntity(gid).method(io.akka.pocketid.application.UserGroupEntity::get).invoke())
        .filter(g -> g.id() != null)
        .toList();
    var claims = cc.forKeyValueEntity(u.id()).method(CustomClaimSetEntity::get).invoke();
    return Dtos.userDto(u, groups, claims);
  }

  // ---- listing / self ---------------------------------------------------------------------

  @Get("/users")
  public HttpResponse list() {
    var forbidden = requireAdmin();
    if (forbidden != null) return forbidden;
    var users = cc.forView().method(UsersView::all).invoke().users().stream().map(this::toDto).toList();
    return HttpResponses.ok(Dtos.page(users));
  }

  @Get("/users/me")
  public HttpResponse myself() {
    var u = me();
    if (u == null) return HttpResponses.ok(err("unauthorized")).withStatus(StatusCodes.UNAUTHORIZED);
    return HttpResponses.ok(toDto(u));
  }

  @Get("/users/{id}")
  public HttpResponse getOne(String id) {
    var forbidden = requireAdmin();
    if (forbidden != null) return forbidden;
    var u = cc.forKeyValueEntity(id).method(UserEntity::get).invoke();
    if (u.id() == null) return HttpResponses.ok(err("not found")).withStatus(StatusCodes.NOT_FOUND);
    return HttpResponses.ok(toDto(u));
  }

  // ---- create / update / delete -----------------------------------------------------------

  public record UpsertUser(
      String username, String email, boolean emailVerified, String firstName, String lastName,
      String displayName, boolean isAdmin, String locale, boolean disabled, List<String> userGroupIds) {}

  @Post("/users")
  public HttpResponse create(UpsertUser body) {
    var forbidden = requireAdmin();
    if (forbidden != null) return forbidden;
    String id = UUID.randomUUID().toString();
    long now = Instant.now().toEpochMilli();
    var created = cc.forKeyValueEntity(id).method(UserEntity::create)
        .invoke(new UserEntity.Create(id, body.username(), body.email(), body.firstName(), body.lastName(),
            body.displayName(), body.isAdmin(), body.userGroupIds() == null ? List.of() : body.userGroupIds(), now));
    return HttpResponses.ok(toDto(created)).withStatus(StatusCodes.CREATED);
  }

  @Put("/users/{id}")
  public HttpResponse update(String id, UpsertUser body) {
    var forbidden = requireAdmin();
    if (forbidden != null) return forbidden;
    long now = Instant.now().toEpochMilli();
    var updated = cc.forKeyValueEntity(id).method(UserEntity::updateProfile)
        .invoke(new UserEntity.UpdateProfile(body.username(), body.email(), body.firstName(), body.lastName(), body.displayName(), body.locale(), now));
    cc.forKeyValueEntity(id).method(UserEntity::setAdmin).invoke(new UserEntity.SetAdmin(body.isAdmin(), now));
    cc.forKeyValueEntity(id).method(UserEntity::setDisabled).invoke(new UserEntity.SetDisabled(body.disabled(), now));
    if (body.userGroupIds() != null) {
      cc.forKeyValueEntity(id).method(UserEntity::setGroups).invoke(new UserEntity.SetGroups(body.userGroupIds(), now));
    }
    return HttpResponses.ok(toDto(cc.forKeyValueEntity(id).method(UserEntity::get).invoke()));
  }

  public record UpdateSelf(String username, String email, String firstName, String lastName, String displayName, String locale) {}

  @Put("/users/me")
  public HttpResponse updateSelf(UpdateSelf body) {
    var u = me();
    if (u == null) return HttpResponses.ok(err("unauthorized")).withStatus(StatusCodes.UNAUTHORIZED);
    long now = Instant.now().toEpochMilli();
    var updated = cc.forKeyValueEntity(u.id()).method(UserEntity::updateProfile)
        .invoke(new UserEntity.UpdateProfile(body.username(), body.email(), body.firstName(), body.lastName(), body.displayName(), body.locale(), now));
    return HttpResponses.ok(toDto(updated));
  }

  @Delete("/users/{id}")
  public HttpResponse delete(String id) {
    var forbidden = requireAdmin();
    if (forbidden != null) return forbidden;
    cc.forKeyValueEntity(id).method(UserEntity::delete).invoke();
    return HttpResponses.ok(java.util.Map.of("status", "deleted"));
  }

  // ---- groups -------------------------------------------------------------------------------

  @Get("/users/{id}/groups")
  public HttpResponse groups(String id) {
    var u = cc.forKeyValueEntity(id).method(UserEntity::get).invoke();
    if (u.id() == null) return HttpResponses.ok(err("not found")).withStatus(StatusCodes.NOT_FOUND);
    var all = cc.forView().method(UserGroupsView::all).invoke().groups();
    var mine = all.stream().filter(g -> u.groupIds().contains(g.id())).toList();
    return HttpResponses.ok(mine);
  }

  public record SetGroupsRequest(List<String> userGroupIds) {}

  @Put("/users/{id}/user-groups")
  public HttpResponse setGroups(String id, SetGroupsRequest body) {
    var forbidden = requireAdmin();
    if (forbidden != null) return forbidden;
    var updated = cc.forKeyValueEntity(id).method(UserEntity::setGroups)
        .invoke(new UserEntity.SetGroups(body.userGroupIds(), Instant.now().toEpochMilli()));
    return HttpResponses.ok(toDto(updated));
  }

  // ---- webauthn credentials (admin view onto another user's passkeys) ---------------------

  @Get("/users/{id}/webauthn-credentials")
  public HttpResponse credentials(String id) {
    var forbidden = requireAdmin();
    if (forbidden != null) return forbidden;
    return HttpResponses.ok(cc.forView().method(io.akka.pocketid.application.WebAuthnCredentialsView::byUser).invoke(id).credentials());
  }

  @Delete("/users/{id}/webauthn-credentials/{credentialId}")
  public HttpResponse deleteCredential(String id, String credentialId) {
    var forbidden = requireAdmin();
    if (forbidden != null) return forbidden;
    cc.forKeyValueEntity(credentialId).method(io.akka.pocketid.application.WebAuthnCredentialEntity::delete).invoke();
    return HttpResponses.ok(java.util.Map.of("status", "deleted"));
  }

  // ---- profile pictures -----------------------------------------------------------------

  @Get("/users/{id}/profile-picture.png")
  public HttpResponse picture(String id) {
    var blob = cc.forKeyValueEntity("user-picture:" + id).method(BlobEntity::get).invoke();
    if (blob.isEmpty()) return HttpResponse.create().withStatus(StatusCodes.NOT_FOUND);
    byte[] bytes = Base64.getDecoder().decode(blob.base64Data());
    ContentType ct = ContentTypes.parse(blob.contentType() == null ? "image/png" : blob.contentType());
    return HttpResponse.create().withStatus(StatusCodes.OK).withEntity(ct, ByteString.fromArray(bytes));
  }

  public record PictureUpload(String base64Data, String contentType) {}

  @Put("/users/{id}/profile-picture")
  public HttpResponse setPicture(String id, PictureUpload body) {
    var forbidden = requireAdmin();
    if (forbidden != null) return forbidden;
    cc.forKeyValueEntity("user-picture:" + id).method(BlobEntity::put).invoke(new BlobEntity.Put("user-picture:" + id, body.contentType(), body.base64Data()));
    return HttpResponses.ok(java.util.Map.of("status", "updated"));
  }

  @Delete("/users/{id}/profile-picture")
  public HttpResponse deletePicture(String id) {
    var forbidden = requireAdmin();
    if (forbidden != null) return forbidden;
    cc.forKeyValueEntity("user-picture:" + id).method(BlobEntity::delete).invoke();
    return HttpResponses.ok(java.util.Map.of("status", "deleted"));
  }

  @Put("/users/me/profile-picture")
  public HttpResponse setMyPicture(PictureUpload body) {
    var u = me();
    if (u == null) return HttpResponses.ok(err("unauthorized")).withStatus(StatusCodes.UNAUTHORIZED);
    cc.forKeyValueEntity("user-picture:" + u.id()).method(BlobEntity::put).invoke(new BlobEntity.Put("user-picture:" + u.id(), body.contentType(), body.base64Data()));
    return HttpResponses.ok(java.util.Map.of("status", "updated"));
  }

  @Delete("/users/me/profile-picture")
  public HttpResponse deleteMyPicture() {
    var u = me();
    if (u == null) return HttpResponses.ok(err("unauthorized")).withStatus(StatusCodes.UNAUTHORIZED);
    cc.forKeyValueEntity("user-picture:" + u.id()).method(BlobEntity::delete).invoke();
    return HttpResponses.ok(java.util.Map.of("status", "deleted"));
  }

  // ---- one-time access (admin-issued) ----------------------------------------------------

  public record OneTimeTokenRequest(Long ttl) {}

  @Post("/users/{id}/one-time-access-token")
  public HttpResponse issueOneTimeToken(String id, OneTimeTokenRequest body) {
    var forbidden = requireAdmin();
    if (forbidden != null) return forbidden;
    long ttlMillis = (body != null && body.ttl() != null ? body.ttl() : 3600) * 1000L;
    String token = OneTimeAccess.randomToken(ttlMillis);
    long now = Instant.now().toEpochMilli();
    cc.forKeyValueEntity(token).method(OneTimeAccessTokenEntity::issue)
        .invoke(new OneTimeAccessTokenEntity.Issue(token, id, now + ttlMillis));
    return HttpResponses.ok(java.util.Map.of("token", token));
  }

  @Post("/users/{id}/one-time-access-email")
  public HttpResponse issueOneTimeEmail(String id, OneTimeTokenRequest body) {
    var forbidden = requireAdmin();
    if (forbidden != null) return forbidden;
    long ttlMillis = (body != null && body.ttl() != null ? body.ttl() : 3600) * 1000L;
    String token = OneTimeAccess.randomToken(ttlMillis);
    long now = Instant.now().toEpochMilli();
    cc.forKeyValueEntity(token).method(OneTimeAccessTokenEntity::issue)
        .invoke(new OneTimeAccessTokenEntity.Issue(token, id, now + ttlMillis));
    // Email send is a documented stub (SPEC scope note B-1: no SMTP fixture in this environment).
    return HttpResponses.ok(java.util.Map.of("status", "sent", "tokenForTesting", token));
  }

  // ---- self-service email verification ----------------------------------------------------

  @Post("/users/me/send-email-verification")
  public HttpResponse sendEmailVerification() {
    var u = me();
    if (u == null) return HttpResponses.ok(err("unauthorized")).withStatus(StatusCodes.UNAUTHORIZED);
    if (u.email() == null || u.email().isEmpty()) return HttpResponses.ok(err("no email on file")).withStatus(StatusCodes.BAD_REQUEST);
    String token = UUID.randomUUID().toString();
    long expiresAt = Instant.now().toEpochMilli() + 24L * 60 * 60_000;
    cc.forKeyValueEntity(u.id()).method(EmailVerificationEntity::issue)
        .invoke(new EmailVerificationEntity.Issue(u.id(), token, u.email(), expiresAt));
    return HttpResponses.ok(java.util.Map.of("status", "sent", "tokenForTesting", token));
  }

  public record VerifyEmailRequest(String token) {}

  @Post("/users/me/verify-email")
  public HttpResponse verifyEmail(VerifyEmailRequest body) {
    var u = me();
    if (u == null) return HttpResponses.ok(err("unauthorized")).withStatus(StatusCodes.UNAUTHORIZED);
    var outcome = cc.forKeyValueEntity(u.id()).method(EmailVerificationEntity::verify)
        .invoke(new EmailVerificationEntity.Verify(body.token(), u.email(), Instant.now().toEpochMilli()));
    if (outcome.result() != EmailVerificationEntity.VerifyResult.OK) {
      return HttpResponses.ok(err("Invalid or expired verification token.")).withStatus(StatusCodes.BAD_REQUEST);
    }
    var updated = cc.forKeyValueEntity(u.id()).method(UserEntity::verifyEmail).invoke(new UserEntity.VerifyEmail(Instant.now().toEpochMilli()));
    return HttpResponses.ok(toDto(updated));
  }
}
