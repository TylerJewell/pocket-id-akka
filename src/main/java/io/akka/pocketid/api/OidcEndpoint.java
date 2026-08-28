package io.akka.pocketid.api;

import akka.http.javadsl.model.HttpHeader;
import akka.http.javadsl.model.HttpResponse;
import akka.http.javadsl.model.StatusCodes;
import akka.javasdk.annotations.Acl;
import akka.javasdk.annotations.http.Get;
import akka.javasdk.annotations.http.HttpEndpoint;
import akka.javasdk.annotations.http.Post;
import akka.javasdk.client.ComponentClient;
import akka.javasdk.http.AbstractHttpEndpoint;
import akka.javasdk.http.HttpResponses;
import com.nimbusds.jwt.JWTClaimsSet;
import io.akka.pocketid.application.AuthnSessionEntity;
import io.akka.pocketid.application.AuthorizationCodeEntity;
import io.akka.pocketid.application.Claims;
import io.akka.pocketid.application.CustomClaimSetEntity;
import io.akka.pocketid.application.DeviceCodeEntity;
import io.akka.pocketid.application.DeviceCodesView;
import io.akka.pocketid.application.OidcClientEntity;
import io.akka.pocketid.application.ParRequestEntity;
import io.akka.pocketid.application.RefreshTokenEntity;
import io.akka.pocketid.application.SigningKeys;
import io.akka.pocketid.application.UserEntity;
import io.akka.pocketid.application.UserGroupEntity;
import io.akka.pocketid.domain.CustomClaim;
import io.akka.pocketid.domain.OidcClient;
import io.akka.pocketid.domain.User;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.time.Instant;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Base64;
import java.util.Date;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.UUID;

/**
 * The OIDC/OAuth2 protocol surface — discovery, JWKS, authorize (+ PAR), token (authorization_code,
 * refresh_token, client_credentials, device_code), introspection, end-session, userinfo, and the
 * RFC 8628 device authorization grant. SPEC-001 rule numbers cited below carry over unchanged from
 * the original OIDC-only slice; rules for the grants this pass adds are numbered from 16.
 */
@Acl(allow = @Acl.Matcher(principal = Acl.Principal.ALL))
@HttpEndpoint("")
public class OidcEndpoint extends AbstractHttpEndpoint {

  public static final String ISSUER = "http://localhost:9127";
  private static final long AUTH_CODE_TTL_MILLIS = 60_000;
  private static final long ACCESS_TOKEN_TTL_MILLIS = 15 * 60_000;
  private static final long REFRESH_TOKEN_TTL_MILLIS = 30L * 24 * 60 * 60_000;
  private static final long DEVICE_CODE_TTL_MILLIS = 5 * 60_000;
  private static final long PAR_TTL_MILLIS = 90_000;
  public static final String SESSION_COOKIE = "pid_session";
  private static final SecureRandom RANDOM = new SecureRandom();

  private final ComponentClient componentClient;

  public OidcEndpoint(ComponentClient componentClient) {
    this.componentClient = componentClient;
  }

  // ---- discovery & keys ---------------------------------------------------------------

  public record OpenIdConfiguration(
      String issuer,
      String authorization_endpoint,
      String token_endpoint,
      String userinfo_endpoint,
      String jwks_uri,
      String introspection_endpoint,
      String end_session_endpoint,
      String pushed_authorization_request_endpoint,
      String device_authorization_endpoint,
      List<String> response_types_supported,
      List<String> code_challenge_methods_supported,
      List<String> grant_types_supported,
      List<String> scopes_supported,
      List<String> id_token_signing_alg_values_supported,
      List<String> subject_types_supported) {}

  @Get("/.well-known/openid-configuration")
  public OpenIdConfiguration discovery() {
    return new OpenIdConfiguration(
        ISSUER,
        ISSUER + "/authorize",
        ISSUER + "/api/oidc/token",
        ISSUER + "/api/oidc/userinfo",
        ISSUER + "/.well-known/jwks.json",
        ISSUER + "/api/oidc/introspect",
        ISSUER + "/api/oidc/end-session",
        ISSUER + "/api/oidc/par",
        ISSUER + "/api/oidc/device/authorize",
        List.of("code"),
        List.of("S256"),
        List.of("authorization_code", "refresh_token", "client_credentials", "urn:ietf:params:oauth:grant-type:device_code"),
        List.of("openid", "profile", "email", "groups"),
        List.of("RS256"),
        List.of("public"));
  }

  @Get("/.well-known/jwks.json")
  public Map<String, Object> jwks() {
    return Map.of("keys", List.of(SigningKeys.publicJwk().toJSONObject()));
  }

  @Get("/.well-known/oauth-authorization-server")
  public OpenIdConfiguration oauthDiscovery() {
    return discovery();
  }

  // ---- test login (stand-in for the browser passkey ceremony; WebAuthnEndpoint is the real one)

  public record LoginRequest(String subject) {}

  public record LoginResponse(String session_id, String subject) {}

  @Post("/login")
  public HttpResponse login(LoginRequest request) {
    var user = userById(request.subject());
    if (user == null || user.id() == null) {
      return errorJson(StatusCodes.BAD_REQUEST, "invalid_request", "Unknown subject.");
    }
    return startSession(user.id());
  }

  public HttpResponse startSession(String subject) {
    String sessionId = UUID.randomUUID().toString();
    sessionEntity(sessionId)
        .method(AuthnSessionEntity::create)
        .invoke(new AuthnSessionEntity.Create(sessionId, subject, Instant.now().toEpochMilli()));
    var body = new LoginResponse(sessionId, subject);
    return HttpResponses.ok(body)
        .addHeader(HttpHeader.parse("Set-Cookie", SESSION_COOKIE + "=" + sessionId + "; Path=/; HttpOnly"));
  }

  // ---- pushed authorization requests (RFC 9126) -----------------------------------------

  public record ParResponse(String request_uri, long expires_in) {}

  @Post("/api/oidc/par")
  public HttpResponse pushedAuthorizationRequest() {
    var q = requestContext().queryParams();
    String clientId = q.getString("client_id").orElse("");
    OidcClient client = clientById(clientId);
    if (client == null) {
      return errorJson(StatusCodes.UNAUTHORIZED, "invalid_client", "The requested OAuth 2.0 Client does not exist.");
    }
    String requestUri = "urn:ietf:params:oauth:request_uri:" + randomToken(24);
    long expiresAt = Instant.now().toEpochMilli() + PAR_TTL_MILLIS;
    componentClient.forKeyValueEntity(requestUri)
        .method(ParRequestEntity::push)
        .invoke(new ParRequestEntity.Push(
            requestUri, clientId, q.getString("redirect_uri").orElse(""), q.getString("response_type").orElse(""),
            q.getString("scope").orElse("openid"), q.getString("state").orElse(null), q.getString("nonce").orElse(null),
            q.getString("code_challenge").orElse(null), q.getString("code_challenge_method").orElse(null), expiresAt));
    return HttpResponses.ok(new ParResponse(requestUri, PAR_TTL_MILLIS / 1000)).withStatus(StatusCodes.CREATED);
  }

  // ---- authorize (rules 3, 4, 5) --------------------------------------------------------

  @Get("/authorize")
  public HttpResponse authorizeGet() {
    return authorize();
  }

  @Post("/authorize")
  public HttpResponse authorizePost() {
    return authorize();
  }

  private HttpResponse authorize() {
    var q = requestContext().queryParams();
    String requestUri = q.getString("request_uri").orElse(null);

    String clientId, redirectUri, responseType, scope, state, nonce, codeChallenge, codeChallengeMethod;
    if (requestUri != null) {
      var pushed = componentClient.forKeyValueEntity(requestUri).method(ParRequestEntity::consume).invoke();
      if (pushed.isEmpty() || pushed.consumed() || Instant.now().toEpochMilli() >= pushed.expiresAtMillis()) {
        return errorJson(StatusCodes.BAD_REQUEST, "invalid_request", "Unknown or expired request_uri.");
      }
      clientId = pushed.clientId();
      redirectUri = pushed.redirectUri();
      responseType = pushed.responseType();
      scope = pushed.scope();
      state = pushed.state_();
      nonce = pushed.nonce();
      codeChallenge = pushed.codeChallenge();
      codeChallengeMethod = pushed.codeChallengeMethod();
    } else {
      clientId = q.getString("client_id").orElse("");
      redirectUri = q.getString("redirect_uri").orElse("");
      responseType = q.getString("response_type").orElse("");
      scope = q.getString("scope").orElse("openid");
      state = q.getString("state").orElse(null);
      nonce = q.getString("nonce").orElse(null);
      codeChallenge = q.getString("code_challenge").orElse(null);
      codeChallengeMethod = q.getString("code_challenge_method").orElse(null);
    }

    OidcClient client = clientById(clientId);
    // rule 3: an untrusted client/redirect_uri is never used as a redirect target
    if (client == null) {
      return errorJson(StatusCodes.BAD_REQUEST, "invalid_client", "The requested OAuth 2.0 Client does not exist.");
    }
    if (redirectUri.isEmpty() || !client.hasRedirectUri(redirectUri)) {
      return errorJson(StatusCodes.BAD_REQUEST, "invalid_request", "redirect_uri does not match a registered callback.");
    }

    if (!"code".equals(responseType)) {
      return redirectWithError(redirectUri, state, "unsupported_response_type", "Only response_type=code is supported.");
    }
    // rule 4: PKCE S256 is mandatory, checked before authentication
    if (codeChallenge == null || codeChallenge.isEmpty() || !"S256".equals(codeChallengeMethod)) {
      return redirectWithError(redirectUri, state, "invalid_request", "PKCE with code_challenge_method=S256 is required.");
    }

    String subject = authenticatedSubject();
    if (subject == null) {
      return errorJson(StatusCodes.UNAUTHORIZED, "login_required", "POST /login first, then retry /authorize with the session cookie or X-Session-Id header.");
    }
    User user = userById(subject);
    if (user == null || user.disabled()) {
      return redirectWithError(redirectUri, state, "access_denied", "This account cannot sign in.");
    }
    // rule 16: a group-restricted client only authorizes members of an allowed group
    if (!client.userGroupAllowed(user.groupIds())) {
      return redirectWithError(redirectUri, state, "access_denied", "This account is not permitted to use this client.");
    }

    String code = UUID.randomUUID().toString();
    long expiresAt = Instant.now().toEpochMilli() + AUTH_CODE_TTL_MILLIS;
    codeEntity(code)
        .method(AuthorizationCodeEntity::issue)
        .invoke(new AuthorizationCodeEntity.Issue(code, clientId, redirectUri, scope, subject, nonce, codeChallenge, expiresAt));
    AuditRecorder.record(componentClient, requestContext(), "CLIENT_AUTHORIZATION", user.id(), user.username(), client.name());

    String location = redirectUri + (redirectUri.contains("?") ? "&" : "?") + "code=" + urlEncode(code)
        + (state != null ? "&state=" + urlEncode(state) : "");
    return HttpResponse.create().withStatus(StatusCodes.FOUND).addHeader(HttpHeader.parse("Location", location));
  }

  private String authenticatedSubject() {
    String sessionId = requestContext().requestHeader("X-Session-Id").map(HttpHeader::value).orElse(null);
    if (sessionId == null) {
      sessionId = requestContext().requestHeader("Cookie")
          .map(HttpHeader::value)
          .map(this::extractSessionCookie)
          .orElse(null);
    }
    if (sessionId == null) return null;
    var session = sessionEntity(sessionId).method(AuthnSessionEntity::get).invoke();
    return session.isEmpty() ? null : session.subject();
  }

  private String extractSessionCookie(String cookieHeader) {
    for (String part : cookieHeader.split(";")) {
      String trimmed = part.trim();
      if (trimmed.startsWith(SESSION_COOKIE + "=")) {
        return trimmed.substring((SESSION_COOKIE + "=").length());
      }
    }
    return null;
  }

  // ---- token (rules 6, 7, 8, 9, 10, 11, 14, 15; grants added: client_credentials, device_code)

  public record TokenResponse(
      String access_token, String token_type, long expires_in, String id_token, String refresh_token) {}

  @Post("/api/oidc/token")
  public HttpResponse token() {
    var q = requestContext().queryParams();
    String grantType = q.getString("grant_type").orElse("");

    if ("client_credentials".equals(grantType)) {
      return clientCredentialsGrant(q);
    }
    if ("urn:ietf:params:oauth:grant-type:device_code".equals(grantType)) {
      return deviceCodeGrant(q);
    }

    String clientId = q.getString("client_id").orElse("");
    String clientSecret = q.getString("client_secret").orElse(null);
    OidcClient client = clientById(clientId);
    if (client == null || !clientAuthenticated(client, clientSecret)) {
      return errorJson(StatusCodes.UNAUTHORIZED, "invalid_client",
          "Client authentication failed (e.g., unknown client, no client authentication included, or unsupported authentication method).");
    }

    return switch (grantType) {
      case "authorization_code" -> authorizationCodeGrant(q, client);
      case "refresh_token" -> refreshTokenGrant(q, client);
      default -> errorJson(StatusCodes.BAD_REQUEST, "unsupported_grant_type",
          "grant_type must be authorization_code, refresh_token, client_credentials, or the device_code grant.");
    };
  }

  private boolean clientAuthenticated(OidcClient client, String presentedSecret) {
    if (client.clientSecret() == null) return true; // public client
    if (presentedSecret == null) return false;
    return MessageDigest.isEqual(
        client.clientSecret().getBytes(StandardCharsets.UTF_8), presentedSecret.getBytes(StandardCharsets.UTF_8));
  }

  /** Rule 16: client_credentials has no end user — the subject of the token is the client itself. */
  private HttpResponse clientCredentialsGrant(akka.javasdk.http.QueryParams q) {
    String clientId = q.getString("client_id").orElse("");
    String clientSecret = q.getString("client_secret").orElse(null);
    OidcClient client = clientById(clientId);
    if (client == null || client.clientSecret() == null || !clientAuthenticated(client, clientSecret)) {
      return errorJson(StatusCodes.UNAUTHORIZED, "invalid_client", "client_credentials requires a confidential, authenticated client.");
    }
    Instant now = Instant.now();
    Instant expiry = now.plusMillis(ACCESS_TOKEN_TTL_MILLIS);
    var claims = new JWTClaimsSet.Builder()
        .issuer(ISSUER).subject(clientId).audience(clientId)
        .issueTime(Date.from(now)).expirationTime(Date.from(expiry))
        .claim("client_id", clientId).claim("scope", q.getString("scope").orElse(""))
        .build();
    String accessToken = SigningKeys.sign(claims);
    return HttpResponses.ok(new TokenResponse(accessToken, "Bearer", ACCESS_TOKEN_TTL_MILLIS / 1000, null, null));
  }

  /** RFC 8628 §3.5 — the client polls with the device_code; the response before approval is
   * authorization_pending, not an HTTP error, per the RFC's own error vocabulary. */
  private HttpResponse deviceCodeGrant(akka.javasdk.http.QueryParams q) {
    String deviceCode = q.getString("device_code").orElse("");
    var state = componentClient.forKeyValueEntity(deviceCode).method(DeviceCodeEntity::get).invoke();
    if (state.isEmpty()) {
      return errorJson(StatusCodes.BAD_REQUEST, "invalid_grant", "Unknown device_code.");
    }
    if (Instant.now().toEpochMilli() >= state.expiresAtMillis()) {
      return errorJson(StatusCodes.BAD_REQUEST, "expired_token", "The device code has expired.");
    }
    return switch (state.status()) {
      case PENDING -> errorJson(StatusCodes.BAD_REQUEST, "authorization_pending", "The user has not yet approved this request.");
      case DENIED -> errorJson(StatusCodes.BAD_REQUEST, "access_denied", "The user denied this request.");
      case CONSUMED -> errorJson(StatusCodes.BAD_REQUEST, "invalid_grant", "This device code has already been exchanged.");
      case APPROVED -> {
        componentClient.forKeyValueEntity(deviceCode).method(DeviceCodeEntity::markConsumed).invoke();
        User user = userById(state.subject());
        List<String> scopes = Arrays.asList(state.scope().split(" "));
        var response = buildTokenResponse(state.clientId(), user, scopes, null, null);
        yield HttpResponses.ok(response);
      }
    };
  }

  private HttpResponse authorizationCodeGrant(akka.javasdk.http.QueryParams q, OidcClient client) {
    String code = q.getString("code").orElse("");
    String redirectUri = q.getString("redirect_uri").orElse("");
    String codeVerifier = q.getString("code_verifier").orElse("");
    long now = Instant.now().toEpochMilli();

    var outcome = codeEntity(code).method(AuthorizationCodeEntity::consume).invoke(new AuthorizationCodeEntity.Consume(now));

    if (outcome.result() == AuthorizationCodeEntity.ConsumeResult.ALREADY_CONSUMED) {
      for (String refreshToken : outcome.revokedRefreshTokens()) {
        refreshEntity(refreshToken).method(RefreshTokenEntity::revoke).invoke();
      }
      return errorJson(StatusCodes.BAD_REQUEST, "invalid_grant", "This authorization code has already been used.");
    }
    if (outcome.result() != AuthorizationCodeEntity.ConsumeResult.OK) {
      return errorJson(StatusCodes.BAD_REQUEST, "invalid_grant", "The authorization code is invalid or expired.");
    }

    var state = outcome.state();
    if (!state.clientId().equals(client.clientId())) {
      return errorJson(StatusCodes.BAD_REQUEST, "invalid_grant", "The authorization code was not issued to this client.");
    }
    if (!state.redirectUri().equals(redirectUri)) {
      return errorJson(StatusCodes.BAD_REQUEST, "invalid_grant", "redirect_uri does not match the one used to obtain the code.");
    }
    if (!pkceMatches(codeVerifier, state.codeChallenge())) {
      return errorJson(StatusCodes.BAD_REQUEST, "invalid_grant", "PKCE verification failed.");
    }

    User user = userById(state.subject());
    List<String> scopes = Arrays.asList(state.scope().split(" "));
    String refreshToken = scopes.contains("offline_access") ? issueRefreshToken(client.clientId(), state.subject(), state.scope()) : null;
    if (refreshToken != null) {
      codeEntity(code).method(AuthorizationCodeEntity::markExchanged).invoke(new AuthorizationCodeEntity.MarkExchanged(refreshToken));
    }

    var response = buildTokenResponse(client.clientId(), user, scopes, state.nonce(), refreshToken);
    return HttpResponses.ok(response);
  }

  private HttpResponse refreshTokenGrant(akka.javasdk.http.QueryParams q, OidcClient client) {
    String token = q.getString("refresh_token").orElse("");
    long now = Instant.now().toEpochMilli();

    var outcome = refreshEntity(token).method(RefreshTokenEntity::checkRedeemable).invoke(new RefreshTokenEntity.Redeem(now));
    if (outcome.result() != RefreshTokenEntity.RedeemResult.OK) {
      return errorJson(StatusCodes.BAD_REQUEST, "invalid_grant", "The refresh token is invalid, expired, or already used.");
    }
    var state = outcome.state();
    if (!state.clientId().equals(client.clientId())) {
      return errorJson(StatusCodes.BAD_REQUEST, "invalid_grant", "The refresh token was not issued to this client.");
    }

    refreshEntity(token).method(RefreshTokenEntity::revoke).invoke();
    User user = userById(state.subject());
    List<String> scopes = Arrays.asList(state.scope().split(" "));
    String newRefreshToken = issueRefreshToken(client.clientId(), state.subject(), state.scope());

    var response = buildTokenResponse(client.clientId(), user, scopes, null, newRefreshToken);
    return HttpResponses.ok(response);
  }

  private String issueRefreshToken(String clientId, String subject, String scope) {
    String token = UUID.randomUUID().toString();
    long expiresAt = Instant.now().toEpochMilli() + REFRESH_TOKEN_TTL_MILLIS;
    refreshEntity(token)
        .method(RefreshTokenEntity::issue)
        .invoke(new RefreshTokenEntity.Issue(token, clientId, subject, scope, expiresAt));
    return token;
  }

  private TokenResponse buildTokenResponse(String clientId, User user, List<String> scopes, String nonce, String refreshToken) {
    Instant now = Instant.now();
    Instant expiry = now.plusMillis(ACCESS_TOKEN_TTL_MILLIS);
    Map<String, Object> userClaims = claimsForUser(user, scopes);

    var accessClaims = new JWTClaimsSet.Builder()
        .issuer(ISSUER).subject(user.id()).audience(clientId)
        .issueTime(Date.from(now)).expirationTime(Date.from(expiry))
        .claim("client_id", clientId).claim("scope", String.join(" ", scopes))
        .build();
    String accessToken = SigningKeys.sign(accessClaims);

    var idClaimsBuilder = new JWTClaimsSet.Builder()
        .issuer(ISSUER).subject(user.id()).audience(clientId)
        .issueTime(Date.from(now)).expirationTime(Date.from(expiry));
    for (var entry : userClaims.entrySet()) {
      if (!"sub".equals(entry.getKey())) idClaimsBuilder.claim(entry.getKey(), entry.getValue());
    }
    if (nonce != null) idClaimsBuilder.claim("nonce", nonce);
    String idToken = SigningKeys.sign(idClaimsBuilder.build());

    return new TokenResponse(accessToken, "Bearer", ACCESS_TOKEN_TTL_MILLIS / 1000, idToken, refreshToken);
  }

  private Map<String, Object> claimsForUser(User user, List<String> scopes) {
    List<String> groupNames = new ArrayList<>();
    List<CustomClaim> merged = new ArrayList<>();
    for (String groupId : user.groupIds()) {
      var group = componentClient.forKeyValueEntity(groupId).method(UserGroupEntity::get).invoke();
      if (group.id() != null) {
        groupNames.add(group.name());
        merged.addAll(componentClient.forKeyValueEntity(groupId).method(CustomClaimSetEntity::get).invoke());
      }
    }
    merged.addAll(componentClient.forKeyValueEntity(user.id()).method(CustomClaimSetEntity::get).invoke());
    return Claims.forScope(user, scopes, groupNames, merged);
  }

  private boolean pkceMatches(String verifier, String challenge) {
    if (verifier == null || verifier.isEmpty() || challenge == null) return false;
    try {
      MessageDigest digest = MessageDigest.getInstance("SHA-256");
      byte[] hash = digest.digest(verifier.getBytes(StandardCharsets.US_ASCII));
      String computed = Base64.getUrlEncoder().withoutPadding().encodeToString(hash);
      return computed.equals(challenge);
    } catch (NoSuchAlgorithmException e) {
      throw new IllegalStateException(e);
    }
  }

  // ---- introspection (RFC 7662) ----------------------------------------------------------

  @Post("/api/oidc/introspect")
  public HttpResponse introspect() {
    var q = requestContext().queryParams();
    String clientId = q.getString("client_id").orElse("");
    String clientSecret = q.getString("client_secret").orElse(null);
    OidcClient client = clientById(clientId);
    if (client == null || !clientAuthenticated(client, clientSecret)) {
      return errorJson(StatusCodes.UNAUTHORIZED, "invalid_client", "Client authentication failed.");
    }
    String token = q.getString("token").orElse("");
    JWTClaimsSet claims = SigningKeys.verify(token);
    if (claims != null) {
      try {
        boolean active = claims.getExpirationTime() != null && claims.getExpirationTime().after(new Date());
        if (!active) return HttpResponses.ok(Map.of("active", false));
        Map<String, Object> body = new LinkedHashMap<>();
        body.put("active", true);
        body.put("sub", claims.getSubject());
        body.put("client_id", claims.getClaim("client_id"));
        body.put("scope", claims.getClaim("scope"));
        body.put("exp", claims.getExpirationTime().toInstant().getEpochSecond());
        body.put("iss", claims.getIssuer());
        return HttpResponses.ok(body);
      } catch (Exception e) {
        return HttpResponses.ok(Map.of("active", false));
      }
    }
    // Not a signed access token — try it as a refresh token.
    var refreshState = refreshEntity(token).method(RefreshTokenEntity::checkRedeemable).invoke(new RefreshTokenEntity.Redeem(Instant.now().toEpochMilli()));
    if (refreshState.result() == RefreshTokenEntity.RedeemResult.OK) {
      return HttpResponses.ok(Map.of(
          "active", true, "sub", refreshState.state().subject(), "client_id", refreshState.state().clientId(),
          "scope", refreshState.state().scope(), "token_type", "refresh_token"));
    }
    return HttpResponses.ok(Map.of("active", false));
  }

  // ---- RP-initiated logout ----------------------------------------------------------------

  @Get("/api/oidc/end-session")
  public HttpResponse endSessionGet() {
    return endSession();
  }

  @Post("/api/oidc/end-session")
  public HttpResponse endSessionPost() {
    return endSession();
  }

  private HttpResponse endSession() {
    var q = requestContext().queryParams();
    String postLogoutRedirectUri = q.getString("post_logout_redirect_uri").orElse(null);
    String state = q.getString("state").orElse(null);
    String idTokenHint = q.getString("id_token_hint").orElse(null);

    String sessionId = requestContext().requestHeader("X-Session-Id").map(HttpHeader::value).orElse(null);
    if (sessionId == null) {
      sessionId = requestContext().requestHeader("Cookie").map(HttpHeader::value).map(this::extractSessionCookie).orElse(null);
    }
    if (sessionId != null) {
      sessionEntity(sessionId).method(AuthnSessionEntity::create).invoke(new AuthnSessionEntity.Create(sessionId, null, 0));
    }

    if (postLogoutRedirectUri == null) {
      return HttpResponses.ok(Map.of("status", "logged_out"));
    }
    // rule 17: only redirect to a client-registered post-logout URI, resolved from id_token_hint's aud
    boolean trusted = false;
    if (idTokenHint != null) {
      JWTClaimsSet claims = SigningKeys.verify(idTokenHint);
      if (claims != null) {
        try {
          String clientId = claims.getAudience().isEmpty() ? null : claims.getAudience().get(0);
          OidcClient client = clientId == null ? null : clientById(clientId);
          trusted = client != null && client.hasPostLogoutRedirectUri(postLogoutRedirectUri);
        } catch (Exception ignored) {
        }
      }
    }
    if (!trusted) {
      return errorJson(StatusCodes.BAD_REQUEST, "invalid_request", "post_logout_redirect_uri is not registered for the client named by id_token_hint.");
    }
    String location = postLogoutRedirectUri + (postLogoutRedirectUri.contains("?") ? "&" : "?")
        + (state != null ? "state=" + urlEncode(state) : "");
    return HttpResponse.create().withStatus(StatusCodes.FOUND).addHeader(HttpHeader.parse("Location", location));
  }

  // ---- RFC 8628 device authorization grant -------------------------------------------------

  public record DeviceAuthorizationResponse(
      String device_code, String user_code, String verification_uri, String verification_uri_complete, long expires_in, long interval) {}

  @Post("/api/oidc/device/authorize")
  public HttpResponse deviceAuthorize() {
    var q = requestContext().queryParams();
    String clientId = q.getString("client_id").orElse("");
    if (clientById(clientId) == null) {
      return errorJson(StatusCodes.UNAUTHORIZED, "invalid_client", "The requested OAuth 2.0 Client does not exist.");
    }
    String deviceCode = UUID.randomUUID().toString();
    String userCode = randomUserCode();
    long expiresAt = Instant.now().toEpochMilli() + DEVICE_CODE_TTL_MILLIS;
    componentClient.forKeyValueEntity(deviceCode)
        .method(DeviceCodeEntity::issue)
        .invoke(new DeviceCodeEntity.Issue(deviceCode, userCode, clientId, q.getString("scope").orElse("openid"), expiresAt, 5));
    String verificationUri = ISSUER + "/device";
    return HttpResponses.ok(new DeviceAuthorizationResponse(
        deviceCode, userCode, verificationUri, verificationUri + "?user_code=" + urlEncode(userCode), DEVICE_CODE_TTL_MILLIS / 1000, 5));
  }

  @Get("/api/oidc/device/info")
  public HttpResponse deviceInfo() {
    String userCode = requestContext().queryParams().getString("code").orElse("");
    var found = deviceCodeByUserCode(userCode);
    if (found == null) return errorJson(StatusCodes.NOT_FOUND, "not_found", "Unknown or expired code.");
    OidcClient client = clientById(found.clientId());
    return HttpResponses.ok(Map.of("client_name", client == null ? found.clientId() : client.name(), "scope", found.scope()));
  }

  public record DeviceVerifyRequest(boolean approve) {}

  @Post("/api/oidc/device/verify")
  public HttpResponse deviceVerify(DeviceVerifyRequest request) {
    String userCode = requestContext().queryParams().getString("code").orElse("");
    String subject = authenticatedSubject();
    if (subject == null) return unauthorized();
    var found = deviceCodeByUserCode(userCode);
    if (found == null) return errorJson(StatusCodes.NOT_FOUND, "not_found", "Unknown or expired code.");
    var updated = componentClient.forKeyValueEntity(found.deviceCode())
        .method(DeviceCodeEntity::decide)
        .invoke(new DeviceCodeEntity.Decide(request.approve(), subject));
    return HttpResponses.ok(Map.of("status", updated.status().name()));
  }

  private DeviceCodeEntity.State deviceCodeByUserCode(String userCode) {
    var rows = componentClient.forView().method(DeviceCodesView::byUserCode).invoke(userCode).codes();
    return rows.isEmpty() ? null : rows.get(0);
  }

  private String randomUserCode() {
    String alphabet = "BCDFGHJKLMNPQRSTVWXYZ23456789"; // unambiguous, matches source's shape
    StringBuilder sb = new StringBuilder("P");
    for (int i = 0; i < 7; i++) sb.append(alphabet.charAt(RANDOM.nextInt(alphabet.length())));
    return sb.toString();
  }

  private String randomToken(int bytes) {
    byte[] b = new byte[bytes];
    RANDOM.nextBytes(b);
    return Base64.getUrlEncoder().withoutPadding().encodeToString(b);
  }

  // ---- userinfo (rules 12, 13) ----------------------------------------------------------

  @Get("/api/oidc/userinfo")
  public HttpResponse userInfoGet() {
    return userInfo();
  }

  @Post("/api/oidc/userinfo")
  public HttpResponse userInfoPost() {
    return userInfo();
  }

  private HttpResponse userInfo() {
    String bearer = requestContext().requestHeader("Authorization").map(HttpHeader::value).orElse(null);
    if (bearer == null || !bearer.startsWith("Bearer ")) {
      return unauthorized();
    }
    JWTClaimsSet claims = SigningKeys.verify(bearer.substring("Bearer ".length()));
    if (claims == null) return unauthorized();
    try {
      if (claims.getExpirationTime() == null || claims.getExpirationTime().before(new Date())) {
        return unauthorized();
      }
    } catch (Exception e) {
      return unauthorized();
    }

    String subject = claims.getSubject();
    User user = userById(subject);
    if (user == null || user.id() == null) return unauthorized();

    String scopeClaim = "";
    try {
      Object raw = claims.getClaim("scope");
      scopeClaim = raw == null ? "" : raw.toString();
    } catch (Exception ignored) {
    }
    List<String> scopes = Arrays.asList(scopeClaim.split(" "));

    Map<String, Object> body = new LinkedHashMap<>(claimsForUser(user, scopes));
    return HttpResponses.ok(body);
  }

  private HttpResponse unauthorized() {
    return errorJson(StatusCodes.UNAUTHORIZED, "request_unauthorized", "The request could not be authorized. Check that you provided valid credentials in the right format.");
  }

  // ---- shared helpers ---------------------------------------------------------------------

  private HttpResponse errorJson(akka.http.javadsl.model.StatusCode status, String error, String description) {
    Map<String, String> body = Map.of("error", error, "error_description", description);
    return HttpResponses.ok(body).withStatus(status);
  }

  private HttpResponse redirectWithError(String redirectUri, String state, String error, String description) {
    String location = redirectUri + (redirectUri.contains("?") ? "&" : "?") + "error=" + urlEncode(error)
        + "&error_description=" + urlEncode(description)
        + (state != null ? "&state=" + urlEncode(state) : "");
    return HttpResponse.create().withStatus(StatusCodes.FOUND).addHeader(HttpHeader.parse("Location", location));
  }

  private String urlEncode(String value) {
    return java.net.URLEncoder.encode(value, StandardCharsets.UTF_8);
  }

  private akka.javasdk.client.KeyValueEntityClient codeEntity(String code) {
    return componentClient.forKeyValueEntity(code);
  }

  private akka.javasdk.client.KeyValueEntityClient refreshEntity(String token) {
    return componentClient.forKeyValueEntity(token);
  }

  private akka.javasdk.client.KeyValueEntityClient sessionEntity(String sessionId) {
    return componentClient.forKeyValueEntity(sessionId);
  }

  private User userById(String id) {
    if (id == null) return null;
    var user = componentClient.forKeyValueEntity(id).method(UserEntity::get).invoke();
    return user.id() == null ? null : user;
  }

  private OidcClient clientById(String clientId) {
    if (clientId == null || clientId.isEmpty()) return null;
    var client = componentClient.forKeyValueEntity(clientId).method(OidcClientEntity::get).invoke();
    return client.clientId() == null ? null : client;
  }
}
