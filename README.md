# pocket-id-akka

A full identity provider: OpenID Connect (authorization-code, refresh, client-credentials,
and device grants; PAR; introspection; RP-initiated logout), WebAuthn passkey sign-in, and
the user, group, client, API-key, audit-log, and configuration management an operator drives
through the same web UI pocket-id ships.

A port of [pocket-id/pocket-id](https://github.com/pocket-id/pocket-id) onto
**Akka**, built with **Akka Specify**.

---

## Where it came from

pocket-id/pocket-id is an OpenID Connect Certified identity provider that lets people sign in
to other applications using a passkey instead of a password. It was ported to derive a
specification format precise enough to regenerate a system on a different stack — the port is
the vehicle, the specification is the deliverable.

**This is the whole system, less native mobile clients, third-party chat-platform
integrations, and pocket-id's S3 backend/CIMD/rate-limit-policy/backup-format specifics,
which needed something this environment does not have (a real S3 target, a hosted CIMD
document, a licensed geo-IP database) to check by running rather than guessing** — the full
reasoning is in `pocket-id-port/specs/SPEC-001-pocket-id.md` §1. An earlier session ported
only the certified OIDC authorization-code core; this one supersedes that scope. The
specifications the port was generated from are in
[TylerJewell/akka-specify-harness](https://github.com/TylerJewell/akka-specify-harness)
under `pocket-id-port/`.

---

## pocket-id/pocket-id → this port

📉 34,497 non-test Go lines → **4,535 Java lines**<br>
📁 225 non-test Go files → **66 Java files**<br>
🖥️ 1 process → **1** process<br>
⚡ 251.4 → **250.5** milliseconds per request, discovery endpoint<br>
🎯 5 of 5 unauthenticated checks agree → **5 of 5**<br>
🧪 0 tests carried over → **24 tests**

Full method and the numbers that did not make this list:
[`bench/REPORT.md`](bench/REPORT.md).

---

## What it does

**Sign-in.** A person registers a passkey and signs in with it (real WebAuthn/FIDO2
verification via `webauthn4j`, not a stand-in) — or, for automation, an API key. An
application redirects them through the OIDC authorization-code flow (PKCE mandatory,
`S256` only), the RFC 8628 device grant for browser-less devices, or `client_credentials` for
machine-to-machine calls. A sign-in code and a refresh token each work exactly once; trading
either a second time is refused and cancels whatever it produced the first time.

**What an application learns depends on what it asked for.** Asking only for identity gets a
bare identifier; asking for more releases a name, an email, or group membership, gated
exactly by the granted scope — plus any custom claims an admin attached to the person or
their group, a user's own claims taking priority over a group's.

**Administration.** Users, groups, OIDC clients, API keys, custom claims, and the ~40-key app
configuration are all managed through the same HTTP API the vendored admin UI calls: create,
update, disable, delete, assign. Every sign-in, account creation, and passkey change is
recorded to an audit log. A person can be invited by a one-time link or a signup token instead
of an admin creating their account directly, and an LDAP directory can be synced in.

Nothing here calls a language model. The work is deciding whether a sign-in or a management
request is genuine, and what to hand back once it is.

---

## Design decisions

**Real WebAuthn, real LDAP, real SCIM push** — not stood in for. Where the prior slice used a
plain `POST /login` in place of passkey verification, this port verifies actual attestation
and assertion signatures (`webauthn4j`), syncs an actual LDAP directory (UnboundID LDAP SDK),
and pushes actual SCIM 2.0 requests to a configured provider.

**One entity per aggregate, one view per list.** Every user, group, client, API key, and
audit-log entry is an Akka `KeyValueEntity`; every admin listing screen is backed by a `View`
consuming from those entities. Membership (`User.groupIds`) has exactly one authoritative
side, read by every endpoint that displays it — see `docs/review-findings.md`'s 2026-08-26
entry for the bug this fixed.

**Narrowed, and named rather than silently dropped**: no S3 storage backend, no CIMD dynamic
client registration, no geo-IP on the audit log, no bespoke per-route rate-limit policy table,
no ZIP backup/export. `specs/SPEC-001-pocket-id.md` §1 gives the reasoning for each.

---

## Running it — the short path

You do not need Java, Maven, or the Akka CLI installed. Akka Specify installs them for you.

**1. Install Akka Specify** in Claude Code:

```
/plugin marketplace add akka/ai-marketplace
/plugin install akka@akka-ai-marketplace
```

Restart Claude Code when it asks.

**2. Give it this prompt:**

> Clone https://github.com/TylerJewell/pocket-id-akka into a new directory and open it.
> Then run /akka:setup to install everything this project needs, and /akka:build to
> compile it, run the tests, and start it locally.

**3. Open** http://localhost:9127.

---

## Running it — the developer path

### Requirements

- Java 21 or newer
- Maven 3.9 or newer
- An Akka download token — run `akka code token` once
- (Only if rebuilding the UI) Node.js and `pnpm`

### Start the service

```bash
mvn compile
akka local run
```

The service starts on **port 9127** and serves the vendored web UI at `/`.

### Build the UI (already built and committed under `src/main/resources/static-resources/`)

```bash
cd gui/webapp
pnpm install --no-frozen-lockfile
BUILD_OUTPUT_PATH=../../src/main/resources/static-resources pnpm build
```

### Try the API directly

```bash
# create the first (admin) account — the setup wizard, same as opening the UI fresh
curl -X POST localhost:9127/api/signup/setup \
  -H 'Content-Type: application/json' \
  -d '{"username":"admin","email":"admin@example.com","firstName":"Admin","lastName":"Person"}'
# -> {"session_id": "...", "subject": "<user id>"}

# list users (admin session required)
curl localhost:9127/api/users -H "X-Session-Id: <session_id from above>"

# register an OIDC client
curl -X POST localhost:9127/api/oidc/clients -H "X-Session-Id: <session_id>" \
  -H 'Content-Type: application/json' \
  -d '{"name":"Test App","isPublic":false,"redirectUris":["http://localhost:9127/callback"]}'

# discovery
curl localhost:9127/.well-known/openid-configuration
```

`docs/question-log.md` row 11 has the full route-prefix map (`/api/*` versus root).

---

## Configuration

The one setting is the port it listens on, written in `src/main/resources/application.conf`:

```
akka.javasdk.dev-mode.http-port = 9127
```

There is no `application-configuration` bootstrap file — the app config's ~40 keys default per
`AppConfigDefaults.java` and are changed at runtime through `PUT /api/application-configuration`
(admin only), matching the source's own runtime-configurable design.

---

## What it took to build

This session (2026-08-26, full-system scope) superseded a 2026-08-21 session that built the
OIDC-only slice. Combined cost across both is tracked by:

```bash
python toolkit/tokens.py --port pocket-id
```

The record of every question, decision, and where the time went is in
[`port-log/`](https://github.com/TylerJewell/akka-specify-harness/tree/main/port-log).

---

## Where it differs from pocket-id/pocket-id

Everything not listed here behaves the same way on purpose, including the parts that look
like mistakes. `specs/SPEC-001-pocket-id.md` §1 has the reasoning for each in full.

- **S3 file-storage backend**: implemented (`FileStorage`), selected via `S3_BUCKET` etc.,
  verified against a real MinIO container this session; falls back to the entity-backed
  ("database") storage when unset, which remains the default.
- **CIMD (Client ID Metadata Document) dynamic client registration**: implemented
  (`CimdSupport`, `OidcEndpoint.resolveCimdClient`, a manual refresh endpoint), gated by an
  admin allowlist and a link-local/multicast SSRF guard, verified against a real throwaway
  local HTTP server standing in for "the client's own metadata host." The `apis`/
  permission-grant resource built on top of CIMD in the source remains out.
- **No geo-IP resolution on audit-log entries.** The IP address is recorded; resolving it to a
  country/city needs a licensed MaxMind GeoLite2 database this environment has no license for.
- **Rate limiting**: implemented in full — all twelve of the source's named per-(policy,
  client-IP) token-bucket policies (`RateLimitPolicies`, `RateLimitEntity`), wired onto the
  same endpoints the source rate-limits, skippable via `disableRateLimiting`.
- **ZIP backup/export/import and the `key-rotate`/`export`/`import` CLI subcommands**:
  implemented as an admin HTTP surface (`BackupEndpoint`) plus a standalone CLI
  (`io.akka.pocketid.cli.PocketIdCli`) that drives it over HTTP rather than opening a database
  file directly — forced by this SDK's entities being reachable only through a running
  service's `ComponentClient`. One real narrowing remains: the source's `import` refuses to
  run while *any* Pocket ID instance is connected to its actor cluster; this port's
  `MaintenanceLockEntity` only serializes imports within one running instance, since there is
  no equivalent cluster-membership concept here to gate on. `encryption-key-rotate` is not
  implemented — this port never built at-rest encryption for the secrets the source rotates a
  key for, and building that encryption is a separate, larger capability this pass did not
  attempt. `key-rotate` is real, persisted rotation (`SigningKeyEntity`) — the JWT signing key
  used to be generated fresh per process and never survive a restart; it is now durable and a
  rotation actually takes effect for every token signed after it.
- **WebAuthn attestation trust-chain/AAGUID-metadata verification is not enforced.**
  Registration and login both perform real signature verification (`webauthn4j`); they do not
  check an authenticator's attestation certificate against a trust store the way a
  high-assurance deployment might.
- **Admin-UI list views are stream-fed, which the source's own screens never were**
  (RENDERING R1). Every admin list screen — users, groups, clients, both audit-log screens,
  signup tokens, and both the self-service and admin per-user passkey lists — subscribes to
  a Server-Sent-Events stream (`SseSupport.java`) instead of fetching once on navigation; a
  dropped connection is handled by the browser's own `EventSource` retry, whose next frame is
  always whole current state.
- **Admin list endpoints apply search/sort/pagination/filters server-side**
  (`ListQueryParams.java`) by filtering, sorting and slicing the view's full result in the
  endpoint, since an Akka View query cannot take a client-supplied sort column, `LIKE`, or
  `IN` predicate the way the source's own SQL-backed query can. One filter is still inert:
  the audit-log screen's `location` (country/city) filter has no field to filter by, since
  geo-IP resolution is the same licensing gap named above.
- **SCIM push is simplified**: always a full create-or-replace per user rather than the
  source's last-modified diff, and providers sync one at a time rather than up to four
  concurrently.
- **LDAP sync is simplified**: reconciles by unique-identifier attribute; the source's DN-cache
  and posixGroup member-resolution fallbacks, admin-group derivation, and profile-picture
  download over LDAP are not implemented.
- **`/authorize` reports an unknown `client_id` as a JSON 400, not a browser redirect.** The
  source responds `302` to its own `/interaction/error?error=...` page even for a client the
  server has never heard of; this port returns the error as JSON directly, since it has no
  server-rendered error page for the vendored SvelteKit frontend to redirect into. Verified by
  running both against the same request (2026-08-27 bench pass).
- **`end-session` on an unregistered `client_id` is a `400`, not a silent `302` to `/logout`.**
  The source ignores an invalid `client_id`/`post_logout_redirect_uri` pair on RP-initiated
  logout and redirects to its generic logout page regardless; this port validates the pair and
  rejects it, which is the stricter (and, for an unregistered redirect target, safer) of the
  two readings of the OIDC RP-Initiated Logout spec. Verified by running both (2026-08-27 bench
  pass).
- **Token introspection with no bearer credentials reports `invalid_client`, not
  `request_unauthorized`.** Both return `401`; the source's message names the missing
  `Authorization` header specifically, this port's names the failed client authentication in
  general terms. Verified by running both (2026-08-27 bench pass).
- **A `HEAD` request to this service's HTTP endpoints hangs rather than answering** — verified
  directly (`curl -I` against the source returns `200` in milliseconds; the identical request
  against this port, on any endpoint including an unrelated JSON one, never returns). This is a
  gap in the Akka SDK's dev-mode HTTP routing (no `@Head` annotation exists to declare one
  explicitly), not application code, so nothing here can close it directly. The one place the
  vendored frontend depended on `HEAD` (`login-wrapper.svelte`'s background-image existence
  check) now uses `GET` instead — RENDERING R3's allowed data-layer diff — since a `GET` is
  observably equivalent for that check and does not hang.

---

## Licence

pocket-id/pocket-id is BSD 2-Clause, © 2024 Elias Schneider. This port reimplements
the behaviour without copied source, and vendors the original's own frontend under
`gui/webapp/` (same licence) per RENDERING.md R3; see
[`ACKNOWLEDGEMENTS.md`](ACKNOWLEDGEMENTS.md).
