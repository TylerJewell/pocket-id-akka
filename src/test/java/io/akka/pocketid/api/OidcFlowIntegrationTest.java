package io.akka.pocketid.api;

import static org.assertj.core.api.Assertions.assertThat;

import akka.javasdk.testkit.TestKitSupport;
import com.nimbusds.jwt.JWTClaimsSet;
import io.akka.pocketid.application.AuthorizationCodeEntity;
import io.akka.pocketid.application.OidcClientEntity;
import io.akka.pocketid.application.SigningKeys;
import io.akka.pocketid.application.UserEntity;
import java.net.URI;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.time.Instant;
import java.util.Base64;
import java.util.List;
import java.util.Map;
import java.util.UUID;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

/**
 * SPEC-001 §5 — the authorization-code round trip and every numbered §3 rule reachable over
 * HTTP. Each test method names the rule(s) it covers. The client and user this port used to
 * seed statically (SeedData) are now real entities, created idempotently before each test.
 */
public class OidcFlowIntegrationTest extends TestKitSupport {

  private static final String CLIENT_ID = "test-client";
  private static final String CLIENT_SECRET = "test-secret";
  private static final String REDIRECT_URI = "http://localhost:9034/callback";

  @BeforeEach
  void seed() {
    var existingClient = componentClient.forKeyValueEntity(CLIENT_ID).method(OidcClientEntity::get).invoke();
    if (existingClient.clientId() == null) {
      componentClient.forKeyValueEntity(CLIENT_ID).method(OidcClientEntity::create).invoke(
          new OidcClientEntity.Create(CLIENT_ID, "Test Client", "seeded for OidcFlowIntegrationTest", CLIENT_SECRET, false,
              List.of(REDIRECT_URI, "https://oidcdebugger.com/debug"), List.of(), Instant.now().toEpochMilli()));
    }
    var existingGroup = componentClient.forKeyValueEntity("everyone").method(io.akka.pocketid.application.UserGroupEntity::get).invoke();
    if (existingGroup.id() == null) {
      componentClient.forKeyValueEntity("everyone").method(io.akka.pocketid.application.UserGroupEntity::create)
          .invoke(new io.akka.pocketid.application.UserGroupEntity.Create("everyone", "everyone", "Everyone", Instant.now().toEpochMilli()));
    }
    var existingUser = componentClient.forKeyValueEntity("alice").method(UserEntity::get).invoke();
    if (existingUser.id() == null) {
      componentClient.forKeyValueEntity("alice").method(UserEntity::create).invoke(
          new UserEntity.Create("alice", "alice", "alice@example.com", "Alice", "Anderson", "Alice Anderson", false, List.of("everyone"), Instant.now().toEpochMilli()));
      componentClient.forKeyValueEntity("alice").method(UserEntity::verifyEmail).invoke(new UserEntity.VerifyEmail(Instant.now().toEpochMilli()));
    }
  }

  private record CodePair(String verifier, String challenge) {}

  private CodePair newPkcePair() {
    String verifier = UUID.randomUUID().toString() + UUID.randomUUID();
    try {
      var digest = MessageDigest.getInstance("SHA-256").digest(verifier.getBytes(StandardCharsets.US_ASCII));
      String challenge = Base64.getUrlEncoder().withoutPadding().encodeToString(digest);
      return new CodePair(verifier, challenge);
    } catch (Exception e) {
      throw new RuntimeException(e);
    }
  }

  private String login(String subject) {
    var body =
        httpClient
            .POST("/login")
            .withRequestBody(new OidcEndpoint.LoginRequest(subject))
            .responseBodyAs(OidcEndpoint.LoginResponse.class)
            .invoke()
            .body();
    return body.session_id();
  }

  private String queryParamFromLocation(String location, String key) {
    String query = URI.create(location).getRawQuery();
    for (String pair : query.split("&")) {
      String[] kv = pair.split("=", 2);
      if (kv[0].equals(key)) return java.net.URLDecoder.decode(kv[1], StandardCharsets.UTF_8);
    }
    return null;
  }

  private String authorizeAndGetCode(String sessionId, String scope, String state, String nonce, String challenge) {
    var response =
        httpClient
            .GET("/authorize")
            .addHeader("X-Session-Id", sessionId)
            .addQueryParameter("response_type", "code")
            .addQueryParameter("client_id", CLIENT_ID)
            .addQueryParameter("redirect_uri", REDIRECT_URI)
            .addQueryParameter("scope", scope)
            .addQueryParameter("state", state)
            .addQueryParameter("nonce", nonce)
            .addQueryParameter("code_challenge", challenge)
            .addQueryParameter("code_challenge_method", "S256")
            .invoke()
            .httpResponse();

    assertThat(response.status().intValue()).isEqualTo(302);
    String location = response.getHeader("Location").get().value();
    assertThat(queryParamFromLocation(location, "state")).isEqualTo(state);
    return queryParamFromLocation(location, "code");
  }

  private OidcEndpoint.TokenResponse exchangeCode(String code, String verifier) {
    return httpClient
        .POST("/api/oidc/token")
        .addQueryParameter("grant_type", "authorization_code")
        .addQueryParameter("code", code)
        .addQueryParameter("redirect_uri", REDIRECT_URI)
        .addQueryParameter("code_verifier", verifier)
        .addQueryParameter("client_id", CLIENT_ID)
        .addQueryParameter("client_secret", CLIENT_SECRET)
        .responseBodyAs(OidcEndpoint.TokenResponse.class)
        .invoke()
        .body();
  }

  @Test
  void discoveryAdvertisesOnlyWhatThisPortImplements() {
    var config =
        httpClient
            .GET("/.well-known/openid-configuration")
            .responseBodyAs(OidcEndpoint.OpenIdConfiguration.class)
            .invoke()
            .body();

    assertThat(config.response_types_supported()).containsExactly("code");
    assertThat(config.code_challenge_methods_supported()).containsExactly("S256");
    assertThat(config.grant_types_supported()).containsExactlyInAnyOrder(
        "authorization_code", "refresh_token", "client_credentials", "urn:ietf:params:oauth:grant-type:device_code");
    assertThat(config.id_token_signing_alg_values_supported()).containsExactly("RS256");
    assertThat(config.token_endpoint()).endsWith("/oidc/token");
    assertThat(config.userinfo_endpoint()).endsWith("/oidc/userinfo");
    assertThat(config.jwks_uri()).endsWith("/.well-known/jwks.json");
  }

  @Test
  @SuppressWarnings("unchecked")
  void jwksExposesOnlyThePublicKey() {
    var body = httpClient.GET("/.well-known/jwks.json").responseBodyAs(Map.class).invoke().body();
    var keys = (List<Map<String, Object>>) body.get("keys");
    assertThat(keys).hasSize(1);
    var key = keys.get(0);
    assertThat(key.get("kty")).isEqualTo("RSA");
    assertThat(key.get("alg")).isEqualTo("RS256");
    assertThat(key).doesNotContainKey("d"); // the RSA private exponent must never be published
  }

  @Test
  void unknownClientAtAuthorizeDoesNotRedirect() {
    // rule 3
    var response =
        httpClient
            .GET("/authorize")
            .addQueryParameter("response_type", "code")
            .addQueryParameter("client_id", "no-such-client")
            .addQueryParameter("redirect_uri", "http://evil.example/cb")
            .addQueryParameter("scope", "openid")
            .invoke()
            .httpResponse();

    assertThat(response.status().intValue()).isEqualTo(400);
    assertThat(response.getHeader("Location")).isEmpty();
  }

  @Test
  void pkceIsMandatory() {
    // rule 4 — client/redirect are valid, so the error goes to the trusted redirect_uri
    String sessionId = login("alice");
    var response =
        httpClient
            .GET("/authorize")
            .addHeader("X-Session-Id", sessionId)
            .addQueryParameter("response_type", "code")
            .addQueryParameter("client_id", CLIENT_ID)
            .addQueryParameter("redirect_uri", REDIRECT_URI)
            .addQueryParameter("scope", "openid")
            .invoke()
            .httpResponse();

    assertThat(response.status().intValue()).isEqualTo(302);
    String location = response.getHeader("Location").get().value();
    assertThat(location).startsWith(REDIRECT_URI);
    assertThat(queryParamFromLocation(location, "error")).isEqualTo("invalid_request");
  }

  @Test
  void fullAuthorizationCodeRoundTrip() throws Exception {
    // rules 5, 6, 7, 9, 10, 11, 12, 13
    String sessionId = login("alice");
    var pkce = newPkcePair();
    String code =
        authorizeAndGetCode(sessionId, "openid profile email groups", "state-1", "nonce-1", pkce.challenge());
    assertThat(code).isNotBlank();

    var tokens = exchangeCode(code, pkce.verifier());
    assertThat(tokens.access_token()).isNotBlank();
    assertThat(tokens.token_type()).isEqualTo("Bearer");
    assertThat(tokens.id_token()).isNotBlank();
    // "offline_access" was not requested, so no refresh token (rule 10)
    assertThat(tokens.refresh_token()).isNull();

    JWTClaimsSet idClaims = SigningKeys.verify(componentClient, tokens.id_token());
    assertThat(idClaims).isNotNull();
    assertThat(idClaims.getSubject()).isEqualTo("alice");
    assertThat(idClaims.getAudience()).contains(CLIENT_ID);
    assertThat(idClaims.getClaim("nonce")).isEqualTo("nonce-1");
    assertThat(idClaims.getClaim("email")).isEqualTo("alice@example.com");
    assertThat(idClaims.getClaim("groups")).isEqualTo(List.of("everyone"));

    var userInfo =
        httpClient
            .GET("/api/oidc/userinfo")
            .addHeader("Authorization", "Bearer " + tokens.access_token())
            .responseBodyAs(Map.class)
            .invoke()
            .body();
    assertThat(userInfo.get("sub")).isEqualTo("alice");
    assertThat(userInfo.get("email")).isEqualTo("alice@example.com");
  }

  @Test
  void wrongPkceVerifierFailsTheExchange() {
    // rule 7
    String sessionId = login("alice");
    var pkce = newPkcePair();
    String code = authorizeAndGetCode(sessionId, "openid", "s", "n", pkce.challenge());

    var response =
        httpClient
            .POST("/api/oidc/token")
            .addQueryParameter("grant_type", "authorization_code")
            .addQueryParameter("code", code)
            .addQueryParameter("redirect_uri", REDIRECT_URI)
            .addQueryParameter("code_verifier", "not-the-right-verifier")
            .addQueryParameter("client_id", CLIENT_ID)
            .addQueryParameter("client_secret", CLIENT_SECRET)
            .invoke()
            .httpResponse();

    assertThat(response.status().intValue()).isEqualTo(400);
  }

  @Test
  void mismatchedRedirectUriFailsTheExchange() {
    // rule 9
    String sessionId = login("alice");
    var pkce = newPkcePair();
    String code = authorizeAndGetCode(sessionId, "openid", "s", "n", pkce.challenge());

    var response =
        httpClient
            .POST("/api/oidc/token")
            .addQueryParameter("grant_type", "authorization_code")
            .addQueryParameter("code", code)
            .addQueryParameter("redirect_uri", "http://localhost:9034/wrong-callback")
            .addQueryParameter("code_verifier", pkce.verifier())
            .addQueryParameter("client_id", CLIENT_ID)
            .addQueryParameter("client_secret", CLIENT_SECRET)
            .invoke()
            .httpResponse();

    assertThat(response.status().intValue()).isEqualTo(400);
  }

  @Test
  void codeIsExchangeableExactlyOnceAndReplayRevokesTheRefreshToken() {
    // rule 8
    String sessionId = login("alice");
    var pkce = newPkcePair();
    String code = authorizeAndGetCode(sessionId, "openid offline_access", "s", "n", pkce.challenge());

    var first = exchangeCode(code, pkce.verifier());
    assertThat(first.refresh_token()).isNotNull();

    var replay =
        httpClient
            .POST("/api/oidc/token")
            .addQueryParameter("grant_type", "authorization_code")
            .addQueryParameter("code", code)
            .addQueryParameter("redirect_uri", REDIRECT_URI)
            .addQueryParameter("code_verifier", pkce.verifier())
            .addQueryParameter("client_id", CLIENT_ID)
            .addQueryParameter("client_secret", CLIENT_SECRET)
            .invoke()
            .httpResponse();
    assertThat(replay.status().intValue()).isEqualTo(400);

    // the refresh token issued by the first (legitimate) exchange must now be dead
    var refreshAttempt =
        httpClient
            .POST("/api/oidc/token")
            .addQueryParameter("grant_type", "refresh_token")
            .addQueryParameter("refresh_token", first.refresh_token())
            .addQueryParameter("client_id", CLIENT_ID)
            .addQueryParameter("client_secret", CLIENT_SECRET)
            .invoke()
            .httpResponse();
    assertThat(refreshAttempt.status().intValue()).isEqualTo(400);
  }

  @Test
  void refreshTokenRotatesAndRejectsReuse() {
    // rule 14
    String sessionId = login("alice");
    var pkce = newPkcePair();
    String code = authorizeAndGetCode(sessionId, "openid offline_access", "s", "n", pkce.challenge());
    var first = exchangeCode(code, pkce.verifier());

    var second =
        httpClient
            .POST("/api/oidc/token")
            .addQueryParameter("grant_type", "refresh_token")
            .addQueryParameter("refresh_token", first.refresh_token())
            .addQueryParameter("client_id", CLIENT_ID)
            .addQueryParameter("client_secret", CLIENT_SECRET)
            .responseBodyAs(OidcEndpoint.TokenResponse.class)
            .invoke()
            .body();

    assertThat(second.refresh_token()).isNotNull();
    assertThat(second.refresh_token()).isNotEqualTo(first.refresh_token());

    var reuseFirst =
        httpClient
            .POST("/api/oidc/token")
            .addQueryParameter("grant_type", "refresh_token")
            .addQueryParameter("refresh_token", first.refresh_token())
            .addQueryParameter("client_id", CLIENT_ID)
            .addQueryParameter("client_secret", CLIENT_SECRET)
            .invoke()
            .httpResponse();
    assertThat(reuseFirst.status().intValue()).isEqualTo(400);
  }

  @Test
  void expiredAuthorizationCodeIsRejected() {
    // rule 15 — issued directly through the entity so expiry does not need a real sleep
    String code = UUID.randomUUID().toString();
    long alreadyExpired = System.currentTimeMillis() - 1_000;
    componentClient
        .forKeyValueEntity(code)
        .method(AuthorizationCodeEntity::issue)
        .invoke(
            new AuthorizationCodeEntity.Issue(
                code, CLIENT_ID, REDIRECT_URI, "openid", "alice", null, "challenge", alreadyExpired));

    var response =
        httpClient
            .POST("/api/oidc/token")
            .addQueryParameter("grant_type", "authorization_code")
            .addQueryParameter("code", code)
            .addQueryParameter("redirect_uri", REDIRECT_URI)
            .addQueryParameter("code_verifier", "whatever")
            .addQueryParameter("client_id", CLIENT_ID)
            .addQueryParameter("client_secret", CLIENT_SECRET)
            .invoke()
            .httpResponse();

    assertThat(response.status().intValue()).isEqualTo(400);
  }

  @Test
  void tokenEndpointRejectsAnUnknownClientWith401() {
    // rule 6, question-log row 3
    var response =
        httpClient
            .POST("/api/oidc/token")
            .addQueryParameter("grant_type", "authorization_code")
            .addQueryParameter("code", "whatever")
            .addQueryParameter("redirect_uri", REDIRECT_URI)
            .addQueryParameter("code_verifier", "whatever")
            .addQueryParameter("client_id", "no-such-client")
            .invoke()
            .httpResponse();

    assertThat(response.status().intValue()).isEqualTo(401);
  }

  @Test
  void userInfoRejectsMissingOrInvalidBearerToken() {
    // rule 12
    var noHeader = httpClient.GET("/api/oidc/userinfo").invoke().httpResponse();
    assertThat(noHeader.status().intValue()).isEqualTo(401);

    var badToken =
        httpClient.GET("/api/oidc/userinfo").addHeader("Authorization", "Bearer garbage").invoke().httpResponse();
    assertThat(badToken.status().intValue()).isEqualTo(401);
  }
}
