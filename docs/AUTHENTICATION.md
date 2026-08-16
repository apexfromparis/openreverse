# Desktop authentication

Last updated: 2026-08-17

## Status and selected flow

Phase E is **PARTIAL**. The secure native-client foundation is implemented and
covered by offline regression tests. A legitimate WorkOS AuthKit public client,
its allowed loopback redirect configuration, and a live end-to-end provider
test are still required before production account authentication can be called
complete.

OpenReverse uses WorkOS AuthKit as a native public client with OAuth 2.0
Authorization Code and PKCE S256. The callback is an ephemeral IPv4 loopback
listener:

```text
http://127.0.0.1:<ephemeral-port>/callback
```

This choice follows WorkOS's current native-application guidance:

- [Authorization URL and native-app redirects](https://workos.com/docs/reference/authkit/authentication/get-authorization-url)
- [Public-client PKCE support](https://workos.com/docs/sdks/node)
- [Authentication and refresh requests](https://workos.com/docs/reference/authkit/authentication)
- [Session logout](https://workos.com/docs/reference/authkit/logout)

The desktop contains only a public client ID. It does not contain a WorkOS API
key or client secret.

## Components and lifecycle

`src/auth` keeps the account boundary separate from analysis and AI:

- `pkce.*` generates a 256-bit random state and a cryptographically random PKCE
  verifier with Windows CNG, then calculates the RFC 7636 S256 challenge.
- `loopback_callback.*` binds only `127.0.0.1`, requests an ephemeral port,
  accepts one bounded HTTP/1.1 request, requires the active Host header and
  exact `/callback` path, and stops after a terminal result, timeout, or cancel.
- `auth_callback.*` accepts only a bounded authorization code plus exact state,
  or a bounded provider error. Duplicate, malformed, unknown, and
  credential-shaped fields are rejected.
- `auth_session.*` owns the explicit state machine and the single pending login
  transaction. It invalidates state and destroys the verifier on success,
  rejection, provider failure, cancellation, or the five-minute timeout.
- `account_api.*` is the provider boundary. The WorkOS implementation performs
  only HTTPS requests and never adds a confidential client secret.
- `secure_credentials.*` stores the refresh credential and bounded account
  metadata in Windows Credential Manager under `OpenReverse.Account.Session`.
  The short-lived access token remains in process memory.
- `auth_client.*` waits for the browser and performs exchanges or refreshes on
  owned worker threads so the Dear ImGui loop remains responsive.

At startup, a stored refresh credential is not treated as proof of a live
session. The account UI enters `ReauthenticationRequired` and requires refresh
or a new browser sign-in. A rotated refresh credential atomically replaces the
previous Credential Manager value after a successful provider response.

## Threat model and invariants

The browser callback carries only a short-lived, single-use authorization code
and state. It never carries an access token, refresh token, API key, license,
session credential, or provider secret. Those values are also prohibited from
command-line arguments, `WM_COPYDATA`, custom URI queries, `.orev` projects,
logs, console output, public configuration, and UI text.

The listener rejects non-loopback peers, arbitrary callback paths, wrong Host
headers, headers over 16 KiB, request targets over 8 KiB, and callbacks with:

- missing or duplicate `code` or `state`;
- malformed percent encoding or unknown fields;
- oversized values;
- `token`, `access_token`, `refresh_token`, `api_key`, `client_secret`,
  `secret`, or `authorization` fields.

State is compared against the only active pending transaction. A mismatch
invalidates that transaction without logging either value. The pending state
and verifier are not persisted. Replays and late callbacks therefore have no
transaction to complete.

The old `openreverse://` token callback, command-line callback forwarding, and
generic `WM_COPYDATA` URI transport are not part of this design and must not be
reintroduced as fallbacks.

## Account and AI credentials

OpenReverse account credentials and user-supplied AI provider credentials are
independent:

```text
OpenReverse.Account.Session   account refresh/session data
OpenReverse/AI/...            user BYOK provider data
```

Signing out deletes only the account credential and clears the in-memory
account access token. It does not delete OpenAI-compatible BYOK keys, projects,
analysis data, or extension state. When a provider session ID is available,
the desktop also opens the official HTTPS provider logout endpoint.

## Configuration

Development builds read the public WorkOS client identifier from:

```powershell
$env:OPENREVERSE_WORKOS_CLIENT_ID = "client_your_public_client_id"
```

The corresponding WorkOS application must be configured as a native/public
client and allow the documented `http://127.0.0.1` loopback redirect behavior.
Do not add an API key, client secret, or other private provider credential to
the executable, repository, installer, environment examples, or frontend.

With no client ID, **Settings > Account** remains safely signed out and explains
that provider configuration is missing. This does not disable any Community
feature.

## Signed-out Community behavior

There is no account wall. Signed-out users can continue to open PE files and
dumps, attach where Windows permits, disassemble, inspect CFG/Xrefs/strings/
globals/structures/offsets/signatures, save and load `.orev`, use Version
Intelligence, load Community extensions, use the CLI, and configure local or
BYOK AI providers.

## Deferred work

Phase E does not implement billing, subscriptions, entitlements, licenses,
hosted AI, Pro distribution, or a commercial backend. Provider configuration
and live login verification remain the Phase E completion blocker. Phase F will
introduce a separate backend boundary for future commercial services; no fake
backend or insecure fallback is created here.
