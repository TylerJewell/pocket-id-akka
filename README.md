# pocket-id-akka

Issues and checks OpenID Connect identity for an application through the
authorization-code sign-in flow — the same decision an identity provider makes
before it hands an application a token.

A port of [pocket-id/pocket-id](https://github.com/pocket-id/pocket-id) onto
**Akka**, built with **Akka Specify**.

---

## Where it came from

pocket-id/pocket-id is an OpenID Connect Certified identity provider that lets
people sign in to other applications using a passkey instead of a password. It was
ported to derive a specification format precise enough to regenerate a system on a
different stack — the port is the vehicle, the specification is the deliverable.

Only one part of pocket-id is rebuilt here: the certified sign-in protocol itself —
discovery, the signing keys, the authorization step, the token exchange, and the
endpoint an application calls to read back who signed in. The specifications the
port was generated from are in
[TylerJewell/akka-specify-harness](https://github.com/TylerJewell/akka-specify-harness)
under `pocket-id-port/`.

---

## pocket-id/pocket-id → this port

📉 909 Go lines (the files implementing this slice) → **651 Java lines**<br>
📁 9 files → **12 files**<br>
🧪 0 tests broken on purpose → **17 tests, 5 rules re-checked against the running original**<br>
⚡ 251.4 milliseconds → **250.5 milliseconds** per discovery-document request

Full method and the numbers that did *not* make this list:
[`bench/REPORT.md`](https://github.com/TylerJewell/akka-specify-harness/blob/main/pocket-id-port/bench/REPORT.md).

---

## What it took to build

⏱️ **0.6 hours** from the first command to the published repository, **0.6** of them active<br>
💬 **359** exchanges with the model<br>
✍️ **178,667** tokens written by the model, **63,638,183** counting everything sent and re-sent<br>
🙋 **0** questions to a human<br>
🧪 **17** tests

```bash
python toolkit/tokens.py --port pocket-id    # turns, tokens, elapsed and active time
```

The record of every question, and where the time went, is in
[`port-log/`](https://github.com/TylerJewell/akka-specify-harness/tree/main/port-log).

---

## What it does

An application redirects someone to sign in, and gets back proof of who they are:

- **Sign-in needs a matching redirect address and a proof-of-possession code.** An
  application registers the addresses it can be sent back to, and every sign-in
  request must prove it can also receive the answer, using a one-time secret only
  the application that started the request knows. Without both, sign-in is refused
  before anyone is asked to authenticate.
- **A sign-in code works exactly once.** Trading it a second time is refused, and
  doing so cancels any long-lived tokens the first trade produced — a code someone
  intercepted and replayed does not get a second chance at those tokens either.
- **What an application learns about someone depends on what it asked for.** Asking
  only for identity gets a bare identifier. Asking for more releases a name, an
  email address, or group membership — and an email address is never released
  alongside a claim about whether it was verified unless there is an email to
  attach that claim to.
- **A long-lived token is replaced, not reused, every time it is spent.** Spending
  it produces a new one and cancels the one just spent, so a token that leaks stops
  working the moment its rightful owner spends it again.

Nothing here calls a language model. The work is deciding whether a sign-in request
is genuine and what to hand back once it is.

---

## Design decisions

**Proof-of-possession is required for every application.** The original only
requires it for applications built to run where a secret cannot be hidden, such as
a phone app. This port requires it always, because the check is cheap and an
application that can also keep a secret is safer with both checks than with one.

**Sign-in uses a stand-in step instead of a physical security key.** Passkey
sign-in needs a real device and a browser; testing this port's sign-in decisions
does not need either, so a plain sign-in step takes their place. Everything after
that step behaves exactly the way it would with a security key.

**One place remembers every sign-in code and token, forever.** The original sweeps
old ones away on a schedule. This port keeps them for as long as it runs, because
tracking their age and deciding when to forget them is a different job from
deciding whether a sign-in request is genuine.

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

**3. Open** http://localhost:9034.

---

## Running it — the developer path

### Requirements

- Java 21 or newer
- Maven 3.9 or newer
- An Akka download token — run `akka code token` once

### Start the service

```bash
mvn compile
akka local run
```

The service starts on **port 9034**.

### Try it

```bash
# sign in as the one seeded person
curl -X POST localhost:9034/login -d '{"subject":"alice"}' -H 'Content-Type: application/json'
# -> {"session_id": "...", "subject": "alice"}

# an application starts a sign-in request (needs a code_challenge — see docs/question-log.md
# row 7 for why it is required here even though the original only requires it sometimes)
curl -i "localhost:9034/authorize?response_type=code&client_id=test-client&redirect_uri=http://localhost:9034/callback&scope=openid+profile+email&state=xyz&code_challenge=<challenge>&code_challenge_method=S256" \
  -H "X-Session-Id: <session_id from above>"
# -> 302, Location carries ?code=...

# the application exchanges the code for tokens
curl -X POST localhost:9034/oidc/token \
  --data-urlencode "grant_type=authorization_code" \
  --data-urlencode "code=<code from above>" \
  --data-urlencode "redirect_uri=http://localhost:9034/callback" \
  --data-urlencode "code_verifier=<the secret the challenge was derived from>" \
  --data-urlencode "client_id=test-client" \
  --data-urlencode "client_secret=test-secret"

# the application reads back who signed in
curl localhost:9034/oidc/userinfo -H "Authorization: Bearer <access_token from above>"
```

---

## Configuration

There are no environment variables. The one setting is the port it listens on,
written in `src/main/resources/application.conf`:

```
akka.javasdk.dev-mode.http-port = 9034
```

The one registered application and the one person who can sign in are seeded in
`application/SeedData.java` rather than configured, because provisioning either
through an API is a different capability from the sign-in protocol this port
rebuilds — see `Where it differs from pocket-id/pocket-id`.

---

## Where it differs from pocket-id/pocket-id

Everything not listed here behaves the same way on purpose, including the parts that
look like mistakes.

- **How someone proves who they are before an application asks for a token.**
  pocket-id verifies a physical passkey. This port asks for a plain sign-in step
  instead (`POST /login`), because rebuilding passkey verification is a different
  capability from the sign-in protocol around it, and everything downstream of that
  step behaves identically either way.
- **Whether proof-of-possession is required for every application.** pocket-id only
  requires it for applications that cannot keep a secret; an application that can
  keep one may skip it. This port always requires it, because the check costs
  nothing extra and there is no application here that benefits from skipping it.
- **Which registered addresses an application may accept.** pocket-id matches an
  exact address or one from an allow-list pattern it stores per application. This
  port matches only an exact address — no pattern list — because the one registered
  application does not need one.
- **Which sign-in and token requests are supported.** pocket-id also lets an
  application ask for a sign-in code up front and hand it to a browser later, sign
  in a device with no browser at all, ask directly whether a token is still good,
  end someone's session across every application at once, and register itself by
  pointing at a document instead of an admin filling in a form. None of these are
  rebuilt here — this port answers only "is this sign-in request genuine, and what
  do we hand back," which is the one decision a conformance suite for the basic
  sign-in flow measures.
- **Registering an application or a person.** pocket-id has an administrator screen
  and an API for both. This port seeds one of each in code instead, because
  provisioning is a different job from deciding whether a sign-in request is
  genuine.
- **How long a sign-in code or a long-lived token is remembered.** pocket-id sweeps
  expired ones away on a schedule. This port keeps every one it has ever issued for
  as long as it runs, with no eviction — `not checked` against any particular
  volume, because no sustained run at production traffic was tried against either
  side.

---

## Licence

pocket-id/pocket-id is BSD 2-Clause, © 2024 Elias Schneider. This port reimplements
the behaviour without copied source; see
[`ACKNOWLEDGEMENTS.md`](ACKNOWLEDGEMENTS.md).
