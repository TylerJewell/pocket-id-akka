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

- **No S3 file-storage backend.** Profile pictures, app images, and client logos are held as
  entity bytes (a KeyValueEntity blob) rather than local disk or S3 — the source's own
  abstraction supports either interchangeably; this port implements the disk-equivalent case
  and does not stand up a real S3-compatible target to check the other by running against it.
- **No CIMD (Client ID Metadata Document) dynamic client registration, and no `apis`/
  permission-grant resource built on top of it.** Correctness there depends on fetching
  another party's hosted document, which nothing in this port's control can check by running.
- **No geo-IP resolution on audit-log entries.** The IP address is recorded; resolving it to a
  country/city needs a licensed MaxMind GeoLite2 database this environment has no license for.
- **Rate limiting is a lighter, undifferentiated guard**, not the source's named per-route
  policy table (login vs. signup vs. one-time-access each get their own bucket and rate in the
  source). The property — abuse resistance exists — is kept; the exact shape is not.
- **No ZIP backup/export/import, and no standalone CLI subcommands** (`key-rotate`,
  `encryption-key-rotate`, `export`, `import`, `healthcheck` as a separate binary mode). An
  Akka service is HTTP-first; `GET /healthz` and `GET /api/version/current` are the genuine
  equivalents that exist, and the rest is named here rather than silently missing.
- **WebAuthn attestation trust-chain/AAGUID-metadata verification is not enforced.**
  Registration and login both perform real signature verification (`webauthn4j`); they do not
  check an authenticator's attestation certificate against a trust store the way a
  high-assurance deployment might.
- **Admin-UI list views are stream-fed, which the source's own screens never were**
  (RENDERING R1). Users, groups, clients, both audit-log screens, and the self-service
  passkey list subscribe to a Server-Sent-Events stream (`SseSupport.java`) instead of
  fetching once on navigation; a dropped connection is handled by the browser's own
  `EventSource` retry, whose next frame is always whole current state. Two secondary
  screens (an admin viewing one user's passkeys, and the signup-token list modal) are not
  yet wired to a stream — see `pocket-id-port/gui/manifest.json`'s `R1_streaming` note.
- **Admin list endpoints ignore search/sort/pagination parameters** and always return the
  whole collection as a single page, unlike the source's server-side paged queries. Invisible
  at the collection sizes this port's own tests exercise; a real divergence at scale. See
  SPEC-001 §1's narrowed-list entry for this.
- **SCIM push is simplified**: always a full create-or-replace per user rather than the
  source's last-modified diff, and providers sync one at a time rather than up to four
  concurrently.
- **LDAP sync is simplified**: reconciles by unique-identifier attribute; the source's DN-cache
  and posixGroup member-resolution fallbacks, admin-group derivation, and profile-picture
  download over LDAP are not implemented.

---

## Licence

pocket-id/pocket-id is BSD 2-Clause, © 2024 Elias Schneider. This port reimplements
the behaviour without copied source, and vendors the original's own frontend under
`gui/webapp/` (same licence) per RENDERING.md R3; see
[`ACKNOWLEDGEMENTS.md`](ACKNOWLEDGEMENTS.md).
