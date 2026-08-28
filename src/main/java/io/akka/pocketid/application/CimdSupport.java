package io.akka.pocketid.application;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import io.akka.pocketid.domain.OidcClient;
import java.net.InetAddress;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.time.Duration;
import java.util.ArrayList;
import java.util.List;

/**
 * Client ID Metadata Documents (CIMD) — `cimd.go`'s resolver, minus the vendored fosite fork:
 * a client whose {@code client_id} is itself an HTTPS URL is resolved by fetching that URL and
 * treating its JSON response body as the client's registration, rather than requiring the client
 * to have been created through this port's admin API first. There is no fixed third party here —
 * the URL is entirely caller-supplied, which is exactly what makes this self-testable with a
 * throwaway local HTTP server standing in for "the client's own metadata host" (question-log
 * verified: `cimd_test.go` in the source does the same with a fake `RoundTripper`).
 */
public final class CimdSupport {
  private CimdSupport() {}

  private static final ObjectMapper MAPPER = new ObjectMapper();
  private static final HttpClient HTTP = HttpClient.newBuilder().connectTimeout(Duration.ofSeconds(5)).build();
  private static final long CACHE_TTL_MILLIS = 60 * 60_000; // 1 hour, matching the source's default cache window

  public static boolean looksLikeCimdUrl(String clientId) {
    return clientId != null && (clientId.startsWith("https://") || clientId.startsWith("http://"));
  }

  /** An admin-configured allowlist entry may be an exact URL or a {@code *} wildcard suffix/prefix
   * match (`*.example.com/*`-shaped) — the same shape `validateCIMDURLAllowlist` accepts in the
   * source. Kept intentionally simple: exact match, or a single leading/trailing {@code *}. */
  public static boolean isAllowlisted(List<String> patterns, String url) {
    for (String pattern : patterns) {
      if (pattern.equals(url)) return true;
      if (pattern.startsWith("*") && url.endsWith(pattern.substring(1))) return true;
      if (pattern.endsWith("*") && url.startsWith(pattern.substring(0, pattern.length() - 1))) return true;
    }
    return false;
  }

  /** Blocks the one class of SSRF target that matters most (cloud metadata / link-local
   * endpoints, RFC 3927 / RFC 4291) — a request to any other host is gated by the admin
   * allowlist above, which is this port's primary access control, matching the source's own
   * layering (allowlist first, an address-range guard as defense in depth on top of it). */
  public static void assertNotLinkLocal(String url) {
    try {
      InetAddress addr = InetAddress.getByName(URI.create(url).getHost());
      if (addr.isLinkLocalAddress() || addr.isMulticastAddress()) {
        throw new IllegalArgumentException("CIMD URL resolves to a link-local/multicast address: " + url);
      }
    } catch (java.net.UnknownHostException e) {
      throw new IllegalArgumentException("CIMD URL host does not resolve: " + url, e);
    }
  }

  public record FetchResult(OidcClient client, String rawJson) {}

  /** Fetches and validates a CIMD document, returning it as an ephemeral (never persisted to
   * {@link OidcClientEntity}) public client. Restricted to {@code token_endpoint_auth_method:
   * none} (a CIMD client can never hold a shared secret this port would need to store) and
   * {@code authorization_code}/{@code device_code} grants, matching `ValidateCIMDClient`. */
  public static FetchResult fetchAndValidate(String url, long nowMillis) throws Exception {
    var request = HttpRequest.newBuilder(URI.create(url))
        .header("User-Agent", "pocket-id-akka/oidc-client-metadata-fetcher")
        .header("Accept", "application/json")
        .timeout(Duration.ofSeconds(5))
        .GET().build();
    HttpResponse<String> response = HTTP.send(request, HttpResponse.BodyHandlers.ofString());
    if (response.statusCode() != 200) {
      throw new IllegalArgumentException("CIMD fetch failed: HTTP " + response.statusCode());
    }
    return validate(url, response.body(), nowMillis);
  }

  public static FetchResult validate(String url, String rawJson, long nowMillis) throws Exception {
    JsonNode doc = MAPPER.readTree(rawJson);

    String authMethod = doc.path("token_endpoint_auth_method").asText("none");
    if (!"none".equals(authMethod)) {
      throw new IllegalArgumentException("CIMD client must use token_endpoint_auth_method=none, got: " + authMethod);
    }

    List<String> grantTypes = toList(doc.path("grant_types"));
    if (grantTypes.isEmpty()) grantTypes = List.of("authorization_code");
    boolean hasAllowedGrant = grantTypes.contains("authorization_code") || grantTypes.contains("urn:ietf:params:oauth:grant-type:device_code");
    if (!hasAllowedGrant) {
      throw new IllegalArgumentException("CIMD client must support authorization_code or device_code, got: " + grantTypes);
    }

    List<String> responseTypes = toList(doc.path("response_types"));
    if (!responseTypes.isEmpty() && !responseTypes.stream().allMatch("code"::equals)) {
      throw new IllegalArgumentException("CIMD client response_types must be [\"code\"], got: " + responseTypes);
    }

    List<String> redirectUris = toList(doc.path("redirect_uris"));
    for (String uri : redirectUris) {
      if (uri.startsWith("javascript:") || uri.startsWith("data:") || !URI.create(uri).isAbsolute()) {
        throw new IllegalArgumentException("CIMD client redirect_uri is not a safe absolute URI: " + uri);
      }
    }

    String clientName = doc.path("client_name").asText(url);
    var client = new OidcClient(url, clientName, "CIMD-resolved client", null, true,
        redirectUris, List.of(), false, List.of(), null, nowMillis, nowMillis);
    return new FetchResult(client, rawJson);
  }

  private static List<String> toList(JsonNode arrayNode) {
    List<String> out = new ArrayList<>();
    if (arrayNode.isArray()) arrayNode.forEach(n -> out.add(n.asText()));
    return out;
  }

  public static boolean isFresh(long fetchedAtMillis, long nowMillis) {
    return nowMillis - fetchedAtMillis < CACHE_TTL_MILLIS;
  }

  public static List<String> parseAllowlist(String json) {
    try {
      return toList(MAPPER.readTree(json == null || json.isEmpty() ? "[]" : json));
    } catch (Exception e) {
      return List.of();
    }
  }
}
