package io.akka.pocketid.domain;

import java.util.List;

/**
 * A seeded OAuth client (SPEC-001 §1 — client management is out of scope; this port seeds one
 * client rather than provisioning through an API). PKCE is mandatory for every client, per
 * SPEC-001 §4's narrowing of the source's per-client {@code PkceEnabled} policy.
 */
public record OidcClient(String clientId, String clientSecret, List<String> redirectUris) {

  public boolean hasRedirectUri(String uri) {
    return redirectUris.contains(uri);
  }
}
