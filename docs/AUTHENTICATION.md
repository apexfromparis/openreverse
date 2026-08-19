# Desktop authentication & account integration

Last updated: 2026-08-19

## Status and architecture

OpenReverse integrates with Supabase Authentication and the authoritative website account endpoint (`GET /api/me`).

```text
SUPABASE AUTH (Email/Password & Sessions)
        ↓
auth.users.id (Canonical UUID)
        ↓
Authoritative GET /api/me (HTTPS Bearer Authentication)
        ↓
Safe account snapshot + Entitlement verification (is_pro_active)
```

The desktop contains only client-safe public configuration (Supabase project URL and publishable/anon key). It does not contain database secrets, service role keys, or Stripe secrets.

## Components and lifecycle

`src/auth` keeps the account boundary separate from binary analysis and local AI:

- `account_api.*` defines the canonical account models (`AccountUser`, `SubscriptionState`, `AccountSnapshot`, `AccountServiceConfig`) and implements `SupabaseAccountApi` for direct HTTPS authentication and profile synchronization (`/api/me`).
- `auth_session.*` manages the explicit session state machine (`SignedOut`, `SigningIn`, `SignedIn`, `Refreshing`, `ReauthenticationRequired`, `Error`, `SigningOut`).
- `secure_credentials.*` securely persists the refresh token in Windows Credential Manager under `OpenReverse.Account.Session`. The short-lived access token remains in process memory.
- `auth_client.*` performs password authentication, session restore, token rotation, and profile refresh on worker threads to keep Dear ImGui responsive.
- `pkce.*` and `loopback_callback.*` provide cryptographic PKCE generation and loopback callback infrastructure for future OAuth provider extensions.

At startup, stored refresh credentials trigger a non-blocking session refresh and `/api/me` profile query. Rotated refresh tokens atomically replace previous credentials in Windows Credential Manager.

## Canonical identity & commercial authority

Identity is strictly canonicalized by Supabase Auth's `auth.users.id` (UUID). Email is not identity.

The desktop is an untrusted client:
- Pro commercial entitlement (`is_pro_active`) is trusted only when verified by the authoritative HTTPS `GET /api/me` endpoint.
- If `/api/me` returns an inconsistent or malformed response (e.g. `plan = "community"` with `is_pro_active = true`), the client fails closed (`isProActive = false`).
- Community features remain 100% functional and offline regardless of authentication or subscription state.

## Account and AI credentials

OpenReverse account credentials and user-supplied BYOK AI provider credentials are completely isolated:

```text
OpenReverse.Account.Session   account refresh token & session identity
OpenReverse/AI/...            user BYOK AI provider keys
```

Signing out deletes only the account credential and clears the in-memory access token. It does not delete user BYOK keys, `.orev` projects, analysis databases, or extension state.

## Configuration & environment variables

Optional environment overrides for development and self-hosted environments:

```powershell
$env:OPENREVERSE_SUPABASE_URL = "https://your-project.supabase.co"
$env:OPENREVERSE_SUPABASE_ANON_KEY = "your-client-publishable-key"
$env:OPENREVERSE_ACCOUNT_API_URL = "https://openreverse.dev"
```

## Signed-out Community behavior

There is no account wall for Community features. Signed-out users can open PE files and memory dumps, disassemble, inspect CFG, cross-references, strings, globals, structures, offsets, signatures, save and load `.orev` projects, use Version Intelligence, load Community extensions, use the CLI, and configure local or BYOK AI providers.
