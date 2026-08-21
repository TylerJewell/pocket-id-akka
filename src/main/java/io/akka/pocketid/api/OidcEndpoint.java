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
import io.akka.pocketid.application.RefreshTokenEntity;
import io.akka.pocketid.application.SeedData;
import io.akka.pocketid.application.SigningKeys;
import io.akka.pocketid.domain.OidcClient;
import io.akka.pocketid.domain.SeededUser;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.time.Instant;
import java.util.Arrays;
import java.util.Base64;
import java.util.Date;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.UUID;

/**
 * The certified OIDC authorization-code surface — SPEC-001. Every rule cited below is a §3 rule
 * number in that spec.
 */
@Acl(allow = @Acl.Matcher(principal = Acl.Principal.ALL))
@HttpEndpoint("")
public class OidcEndpoint extends AbstractHttpEndpoint {

  private static final String ISSUER = "http://localhost:9034";
  private static final long AUTH_CODE_TTL_MILLIS = 60_000; // SPEC-001 §4 assumed rule
  private static final long ACCESS_TOKEN_TTL_MILLIS = 15 * 60_000; // SPEC-001 §4 assumed rule
  private static final long REFRESH_TOKEN_TTL_MILLIS = 30L * 24 * 60 * 60_000; // matches source, provider.go:39
  private static final String SESSION_COOKIE = "pid_session";

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
        ISSUER + "/oidc/token",
        ISSUER + "/oidc/userinfo",
        ISSUER + "/.well-known/jwks.json",
        List.of("code"),
        List.of("S256"),
        List.of("authorization_code", "refresh_token"),
        List.of("openid", "profile", "email", "groups"),
        List.of("RS256"),
        List.of("public"));
  }

  @Get("/.well-known/jwks.json")
  public Map<String, Object> jwks() {
    return Map.of("keys", List.of(SigningKeys.publicJwk().toJSONObject()));
  }

  // ---- test login (stand-in for passkey auth, SPEC-001 §1) ----------------------------

  public record LoginRequest(String subject) {}

  public record LoginResponse(String session_id, String subject) {}

  @Post("/login")
  public HttpResponse login(LoginRequest request) {
    var user = SeedData.userBySubject(request.subject());
    if (user == null) {
      return errorJson(StatusCodes.BAD_REQUEST, "invalid_request", "Unknown subject.");
    }
    String sessionId = UUID.randomUUID().toString();
    sessionEntity(sessionId)
        .method(AuthnSessionEntity::create)
        .invoke(new AuthnSessionEntity.Create(sessionId, request.subject(), Instant.now().toEpochMilli()));
    var body = new LoginResponse(sessionId, request.subject());
    return HttpResponses.ok(body)
        .addHeader(HttpHeader.parse("Set-Cookie", SESSION_COOKIE + "=" + sessionId + "; Path=/; HttpOnly"));
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
    String clientId = q.getString("client_id").orElse("");
    String redirectUri = q.getString("redirect_uri").orElse("");
    String responseType = q.getString("response_type").orElse("");
    String scope = q.getString("scope").orElse("openid");
    String state = q.getString("state").orElse(null);
    String nonce = q.getString("nonce").orElse(null);
    String codeChallenge = q.getString("code_challenge").orElse(null);
    String codeChallengeMethod = q.getString("code_challenge_method").orElse(null);

    OidcClient client = SeedData.clientById(clientId);
    // rule 3: an untrusted client/redirect_uri is never used as a redirect target
    if (client == null) {
      return errorJson(StatusCodes.BAD_REQUEST, "invalid_client", "The requested OAuth 2.0 Client does not exist.");
    }
    if (redirectUri.isEmpty() || !client.hasRedirectUri(redirectUri)) {
      return errorJson(StatusCodes.BAD_REQUEST, "invalid_request", "redirect_uri does not match a registered callback.");
    }

    // From here on redirect_uri is trusted, so errors are delivered to it (matches the source's
    // policy of only trusting the redirect once client + redirect_uri are validated).
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

    String code = UUID.randomUUID().toString();
    long expiresAt = Instant.now().toEpochMilli() + AUTH_CODE_TTL_MILLIS;
    codeEntity(code)
        .method(AuthorizationCodeEntity::issue)
        .invoke(new AuthorizationCodeEntity.Issue(code, clientId, redirectUri, scope, subject, nonce, codeChallenge, expiresAt));

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

  // ---- token (rules 6, 7, 8, 9, 10, 11, 14, 15) -----------------------------------------

  public record TokenResponse(
      String access_token,
      String token_type,
      long expires_in,
      String id_token,
      String refresh_token) {}

  @Post("/oidc/token")
  public HttpResponse token() {
    var q = requestContext().queryParams();
    String grantType = q.getString("grant_type").orElse("");
    String clientId = q.getString("client_id").orElse("");
    String clientSecret = q.getString("client_secret").orElse(null);

    OidcClient client = SeedData.clientById(clientId);
    if (client == null || !clientAuthenticated(client, clientSecret)) {
      // rule 6: matches the source's status code (question-log row 3), not just its body
      return errorJson(
          StatusCodes.UNAUTHORIZED,
          "invalid_client",
          "Client authentication failed (e.g., unknown client, no client authentication included, or unsupported authentication method).");
    }

    return switch (grantType) {
      case "authorization_code" -> authorizationCodeGrant(q, client);
      case "refresh_token" -> refreshTokenGrant(q, client);
      default -> errorJson(StatusCodes.BAD_REQUEST, "unsupported_grant_type", "grant_type must be authorization_code or refresh_token.");
    };
  }

  private boolean clientAuthenticated(OidcClient client, String presentedSecret) {
    if (client.clientSecret() == null) return true; // public client
    if (presentedSecret == null) return false;
    // constant-time: a client secret is a credential, and a length/early-exit compare
    // leaks it one byte at a time through response timing
    return MessageDigest.isEqual(
        client.clientSecret().getBytes(StandardCharsets.UTF_8), presentedSecret.getBytes(StandardCharsets.UTF_8));
  }

  private HttpResponse authorizationCodeGrant(akka.javasdk.http.QueryParams q, OidcClient client) {
    String code = q.getString("code").orElse("");
    String redirectUri = q.getString("redirect_uri").orElse("");
    String codeVerifier = q.getString("code_verifier").orElse("");
    long now = Instant.now().toEpochMilli();

    var outcome = codeEntity(code).method(AuthorizationCodeEntity::consume).invoke(new AuthorizationCodeEntity.Consume(now));

    if (outcome.result() == AuthorizationCodeEntity.ConsumeResult.ALREADY_CONSUMED) {
      // rule 8: replay of a consumed code revokes every refresh token it produced
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
    // rule 9
    if (!state.redirectUri().equals(redirectUri)) {
      return errorJson(StatusCodes.BAD_REQUEST, "invalid_grant", "redirect_uri does not match the one used to obtain the code.");
    }
    // rule 7: PKCE verification
    if (!pkceMatches(codeVerifier, state.codeChallenge())) {
      return errorJson(StatusCodes.BAD_REQUEST, "invalid_grant", "PKCE verification failed.");
    }

    SeededUser user = SeedData.userBySubject(state.subject());
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

    // rule 14: rotate — revoke the presented token, issue a new one
    refreshEntity(token).method(RefreshTokenEntity::revoke).invoke();
    SeededUser user = SeedData.userBySubject(state.subject());
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

  private TokenResponse buildTokenResponse(String clientId, SeededUser user, List<String> scopes, String nonce, String refreshToken) {
    Instant now = Instant.now();
    Instant expiry = now.plusMillis(ACCESS_TOKEN_TTL_MILLIS);
    Map<String, Object> userClaims = Claims.forScope(user, scopes);

    var accessClaims = new JWTClaimsSet.Builder()
        .issuer(ISSUER)
        .subject(user.subject())
        .audience(clientId)
        .issueTime(Date.from(now))
        .expirationTime(Date.from(expiry))
        .claim("client_id", clientId)
        .claim("scope", String.join(" ", scopes))
        .build();
    String accessToken = SigningKeys.sign(accessClaims);

    var idClaimsBuilder = new JWTClaimsSet.Builder()
        .issuer(ISSUER)
        .subject(user.subject())
        .audience(clientId)
        .issueTime(Date.from(now))
        .expirationTime(Date.from(expiry));
    for (var entry : userClaims.entrySet()) {
      if (!"sub".equals(entry.getKey())) idClaimsBuilder.claim(entry.getKey(), entry.getValue());
    }
    if (nonce != null) idClaimsBuilder.claim("nonce", nonce);
    String idToken = SigningKeys.sign(idClaimsBuilder.build());

    return new TokenResponse(accessToken, "Bearer", ACCESS_TOKEN_TTL_MILLIS / 1000, idToken, refreshToken);
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

  // ---- userinfo (rules 12, 13) ----------------------------------------------------------

  @Get("/oidc/userinfo")
  public HttpResponse userInfoGet() {
    return userInfo();
  }

  @Post("/oidc/userinfo")
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
    SeededUser user = SeedData.userBySubject(subject);
    if (user == null) return unauthorized();

    String scopeClaim = "";
    try {
      Object raw = claims.getClaim("scope");
      scopeClaim = raw == null ? "" : raw.toString();
    } catch (Exception ignored) {
    }
    List<String> scopes = Arrays.asList(scopeClaim.split(" "));

    Map<String, Object> body = new LinkedHashMap<>(Claims.forScope(user, scopes));
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
}
