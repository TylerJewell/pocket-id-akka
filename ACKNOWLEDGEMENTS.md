# Acknowledgements

This project is a port of **[pocket-id/pocket-id](https://github.com/pocket-id/pocket-id)**,
read and run against a checkout of its `main` branch at commit
`0bf0f3922dbc12ff95770fddedf03d340ce43898` (2026-08-20).

## Licence

pocket-id/pocket-id is **BSD 2-Clause**, © 2024 Elias Schneider. A copy of that licence
is included as `LICENSE-pocket-id`.

## What was copied

**The backend: no source.** No Go file, fragment or expression from pocket-id's
`backend/` appears here; every file in `src/` was written for this project. The things
carried across deliberately are wire-level details that describe the *protocol and API
surface*, not the implementation, because the vendored frontend (below) and any real
relying party need to see them identically on both systems: OAuth2/OIDC field names and
error-response shapes (for example `{"error":"invalid_client","error_description":"..."}`,
established by running the real source in Docker —
`pocket-id-port/docs/question-log.md`, `pocket-id-port/probes/probe_01.py`); the ~90 HTTP
route paths under `/api/*` the vendored frontend's own `api-service.ts` already calls
(`internal/bootstrap/router_bootstrap.go`); the `search`/`sort[column]`/`sort[direction]`/
`pagination[page]`/`pagination[limit]`/`filters[field][i]` query-parameter names
`list-request.type.ts`'s `ListRequestOptions` already sends on every admin list request
(`ListQueryParams.java`, added 2026-08-27 to read them server-side); the `AppConfigDefaults` configuration-key
names (`sessionDuration`, `webauthnUserVerification`, `smtpPassword`, and the rest of the
~40-key set) the same frontend's settings screens already read and write by name; and
standard-protocol literals this port did not invent (LDAP filter syntax, SCIM's
`urn:ietf:params:scim:schemas:core:2.0:User` schema URN, RFC 8628 grant-type strings).
Route paths and config-key names are listed here as one class rather than individually
because both are drawn directly from the vendored frontend this port repoints
(RENDERING.md R3, below) rather than typed independently by this port and found to
match — matching was the requirement, not a coincidence.

**The web interface: vendored verbatim, deliberately.** `gui/webapp/` is pocket-id's own
`frontend/` (SvelteKit), copied unchanged except for `lib/services/app-config-service.ts`
(one endpoint's request/response shape, `docs/webapp-diff.md`-style change noted in
`pocket-id-port/gui/manifest.json`'s `data_layer_diff`). This is RENDERING.md R3's rule —
the interface that already exists is the one the port ships — and is licensed
identically to the rest of pocket-id (BSD 2-Clause, same `LICENSE-pocket-id`), which
permits this. Listed in `.vendored` at the repository root and skipped by
`toolkit/source_hygiene.py`/`toolkit/copied_strings.py` as vendored rather than authored.

## What is derived

The behaviour is. Every rule in `pocket-id-port/specs/SPEC-001-pocket-id.md` §3 was
established by reading the source's `backend/internal/oidc` package and
`well_known_controller.go`, then running the real system — both the published Docker
image (`pocketid/pocket-id:v2`) directly, and its own configuration of
`github.com/ory/fosite`, the OAuth2/OIDC library the source delegates the actual
protocol mechanics to. This port has no equivalent library to depend on, so
`AuthorizationCodeEntity`, `RefreshTokenEntity`, `SigningKeys`, and the grant logic in
`OidcEndpoint` reimplement the parts of that behaviour SPEC-001 §1 puts in scope.

**Superseded note, kept for history:** an earlier session (2026-08-21) scoped this port
to the OIDC protocol surface alone and stood in a minimal `POST /login` in place of
passkey authentication, on the reasoning that a relying party speaking OIDC to either
system never sees how the user signed in. The 2026-08-26 session re-scoped the port to
the whole system (port-log event B-1) and replaced that stand-in with real FIDO2/WebAuthn
verification (`WebAuthnSupport`, via the third-party `webauthn4j` library — see "Also
used" below) — attestation and assertion signatures are actually checked, not asserted
by a test-only shortcut. `POST /login` still exists, unauthenticated, as a
test/development convenience the source has no equivalent of; see `README.md` under
`Where it differs from pocket-id/pocket-id`.

## Also used

- **Akka** (Akka SDK for Java, BSL 1.1) — the platform this port is built on.
- **Nimbus JOSE + JWT** (Apache License 2.0) — RSA key generation and RS256 JWT
  signing/verification for the ID token, access token, and JWKS document.
- **webauthn4j** (Apache License 2.0) — FIDO2/WebAuthn attestation and assertion
  cryptographic verification (`WebAuthnSupport`), replacing the OIDC-slice's login
  stand-in once the port's scope grew to the whole system.
- **UnboundID LDAP SDK for Java, Standard Edition** (multi-licensed — GPLv2, LGPLv2.1,
  or the UnboundID LDAPSDK Free Use License; confirmed from the jar's own bundled
  `LICENSE*.txt` files) — the directory client `LdapSync` uses to bind to and search a
  real LDAP server.
- **Docker** was used to run the published `pocketid/pocket-id:v2` image for the
  question-log evidence and `probes/probe_01.py`; nothing from the image was copied.
