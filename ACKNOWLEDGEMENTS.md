# Acknowledgements

This project is a port of **[pocket-id/pocket-id](https://github.com/pocket-id/pocket-id)**,
read and run against a checkout of its `main` branch at commit
`0bf0f3922dbc12ff95770fddedf03d340ce43898` (2026-08-20).

## Licence

pocket-id/pocket-id is **BSD 2-Clause**, © 2024 Elias Schneider. A copy of that licence
is included as `LICENSE-pocket-id`.

## What was copied

**The backend: no source.** No Go file, fragment or expression from pocket-id's
`backend/` appears here; every file in `src/` was written for this project. The only
things carried across deliberately are wire-level details that describe the *protocol*,
not the implementation: field names and error-response shapes (for example
`{"error":"invalid_client","error_description":"..."}`) that a relying party sending
requests to either system needs to see identically, established by running the real
source in Docker (`pocket-id-port/docs/question-log.md`, `pocket-id-port/probes/probe_01.py`).

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

One capability is deliberately **not** derived from the source: passkey/WebAuthn
authentication. The source's whole sign-in experience is built on it; this port
stands in a minimal `POST /login` that mints the same kind of authenticated session,
because SPEC-001 §1 scopes this port to the OIDC protocol surface a relying party
speaks, not the identity provider's own login UI. See `README.md` under
`Where it differs from pocket-id/pocket-id` and `SPEC-001-pocket-id.md` §1.

## Also used

- **Akka** (Akka SDK for Java, BSL 1.1) — the platform this port is built on.
- **Nimbus JOSE + JWT** (Apache License 2.0) — RSA key generation and RS256 JWT
  signing/verification for the ID token, access token, and JWKS document.
- **Docker** was used to run the published `pocketid/pocket-id:v2` image for the
  question-log evidence and `probes/probe_01.py`; nothing from the image was copied.
