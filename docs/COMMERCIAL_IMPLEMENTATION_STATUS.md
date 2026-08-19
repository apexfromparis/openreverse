# Commercial implementation status

Last reviewed: 2026-08-17

Canonical version: `2.0.0`

This document tracks implementation evidence and release gates from Phase B
through Phase Q. A phase is `DONE` only after its tests, Release build, smoke
checks, documentation, and repository review pass.

## Status definitions

- `NOT STARTED`: no production implementation exists.
- `PARTIAL`: useful implementation exists but the release gate is not met.
- `BLOCKED`: safe completion requires an external decision, credential, account,
  certificate, legal review, or an unfinished prerequisite phase.
- `READY`: prerequisites are met and implementation can begin.
- `DONE`: every documented release-gate item has passed.

## Phase B — Project persistence

Status: `DONE`

Implementation evidence:

- `src/core/project.*` implements the bounded version-1 `.orev` schema,
  canonical SHA-256 integrity check, explicit migration boundary, target hash
  verification, and flushed temporary-file replacement.
- `src/core/analysis_session.*` owns the canonical `AnalysisDatabase`, project
  state, annotations/bookmarks, dirty/save-as state, and persisted evidence
  rebasing.
- `src/app/application.*` exposes Open Project, Save, Save As, target
  locate/mismatch choices, project shortcuts/status, and useful UI restoration.
- `src/ui/panels/analysis_panel.*`, `bookmarks_panel.*`, and
  `offsets_panel.cpp` persist real user annotations, RVA bookmarks, and
  user-defined offsets.
- `tests/core_tests.cpp` covers full state round-trip, atomic replacement,
  malformed/corrupted input, unsupported versions, matching/changed/missing
  targets, session rebasing, and changed-target suppression.
- `docs/PROJECT_FORMAT.md` documents the schema, limits, integrity scope,
  mismatch behavior, and migration policy.

Implementation checklist:

- [x] Add a bounded, versioned `openreverse-project` schema.
- [x] Preserve target identity/reference, annotations, bookmarks, structures,
  offsets, signatures, migration decisions, settings, and useful UI state.
- [x] Add SHA-256 integrity verification and explicit schema errors.
- [x] Save atomically through a flushed sibling file and replace operation.
- [x] Verify missing targets and SHA-256 mismatch without silently restoring
  target-bound state.
- [x] Add an incremental `AnalysisSession` ownership boundary.
- [x] Add Open Project, Save Project, and Save Project As desktop actions.
- [x] Test round-trip, malformed/corrupted files, unsupported versions, missing
  target, hash mismatch, and atomic replacement.
- [x] Pass Release build, installer build, CTest, and CLI smoke tests.

Release-gate verification on 2026-08-16:

- `cmake --build --preset windows-x64-release --parallel`: passed; application
  and `OpenReverse-2.0.0-Setup.exe` built.
- `ctest --test-dir build/windows-x64 -C Release --output-on-failure`: 1/1
  passed.
- CLI `--help`, `--version`, and `open OpenReverseTestFixture.exe`: exit code 0.
- Repository diff reviewed with the pre-existing `src/main.cpp` and
  `src/ui/panels/ai_copilot.cpp` authentication work left outside this phase's
  commit.

## Phase C — Version Intelligence core

Status: `DONE`

Implementation evidence:

- `src/core/version_intelligence.*` implements identity-backed old/new models,
  deterministic candidate indexes, staged multi-signal matching, conservative
  graph refinement, explicit result states, typed migration candidates,
  progress, and cancellation.
- `src/core/binary_diff.*` normalizes operand roles while retaining semantic
  constants, stack roles, CFG topology, referenced-data roles, calls, runtime
  boundaries, signatures, and separate structure-field evidence.
- `src/core/project.*` stores an optional bounded Version Intelligence section
  without changing the version-1 `.orev` schema; projects without the additive
  section remain compatible.
- `src/core/analysis_session.*` owns accept/reject/reset decisions, validates
  accepted candidates, preserves safe decisions across recomputation, and
  mirrors review results into persistent migration records.
- `src/ui/panels/version_intelligence_panel.*` provides a real old/new workflow,
  structured evidence and change deltas, inspection/navigation, decisions,
  background progress, cancellation, and explicit errors.
- `docs/VERSION_INTELLIGENCE.md` documents the experimental workflow, algorithm,
  migration rules, trust boundary, limitations, and controlled fixtures.

Implementation checklist:

- [x] Add an identity-backed old/new comparison model with explicit function,
  global, signature, offset, structure-field, and user-decision results.
- [x] Extend normalized fingerprints and build deterministic indexes before
  expensive candidate scoring.
- [x] Add staged matching, structured evidence, explicit states, deterministic
  change summaries, and conservative graph refinement.
- [x] Migrate signatures and typed offsets without first-match-wins behavior.
- [x] Persist accepted/rejected/reset decisions without breaking version-1
  `.orev` projects.
- [x] Add a real Version Intelligence workspace with inspection, navigation,
  accept/reject/reset, progress, cancellation, and error reporting.
- [x] Cover moved/changed/ambiguous/removed/new/false-positive functions,
  signatures, globals, fields, and graph refinement with controlled fixtures.
- [x] Pass a clean Release configure/build, installer, CTest, CLI, public-source,
  credential, artifact, local-path, diff, and normal-push gate.

Release-gate evidence (2026-08-16):

- Exact public `HEAD` built from a detached clean worktree into
  `build/windows-x64-phase-c-clean`; application, test fixture, and
  `OpenReverse-2.0.0-Setup.exe` were produced.
- `ctest`: 1/1 passed; CLI `--help`, `--version`, and fixture analysis exited 0.
- Setup/Portable packaging and SHA-256 generation passed.
- Public-source, credential-shaped value, generated-artifact, local-path,
  protected-file, diff, and repository scans passed.
- Normal, non-force push completed; local and remote `main` both resolve to
  `16af2fd3a293927e2895cc6d053db37ce49beb47`.
- Private commercialization documents and the pre-existing authentication work
  in `src/main.cpp` and `src/ui/panels/ai_copilot.cpp` remained local and outside
  every public commit.

Gate: Phase C is complete. Phase D and later phases were not started by this
implementation.

## Phase D — Community/Pro extension boundary

Status: `DONE`

Implementation evidence:

- `sdk/include/openreverse/extension.h` defines the fixed-layout Windows x64 C
  ABI v1, stable result model, capabilities, caller-owned buffer contract,
  descriptor, host function table, and lifecycle callbacks.
- `src/extensions/extension_manifest.*` and `extension_manager.*` implement
  bounded manifest discovery, compatibility/capability checks, canonical full
  paths, restricted DLL search flags, transactional registration, lifecycle,
  reverse-order shutdown, and diagnostics.
- `src/app/application.*` exposes approved read-only target/function views,
  navigation, commands, host-rendered text panels, and extension diagnostics
  without exposing internal C++ or Dear ImGui types.
- `.orev` version 1 preserves bounded extension-owned JSON objects even when the
  owning extension is absent.
- `examples/hello_extension` builds against the public header alone and is not
  bundled by the production installer.
- `tests/core_tests.cpp` and purpose-built DLL fixtures cover compatible and
  incompatible loading, malformed inputs, failures, lifecycle callbacks,
  project state, and zero-extension operation.
- `docs/EXTENSIONS.md` documents the factual SDK contract and states that native
  extensions are trusted in-process code, not sandboxed.
- Legal review of historical MIT code and ownership remains required before
  proprietary reuse decisions.

Implementation checklist:

- [x] Publish a fixed-width, structure-sized, version-1 C ABI without STL,
  internal C++ classes, Dear ImGui, or allocator ownership across the DLL edge.
- [x] Expose bounded read-only active-target/function queries, navigation,
  command registration, host-rendered text panels, and extension-owned project
  state through capability-scoped host functions.
- [x] Add a bounded manifest with strict identifiers, semantic versions,
  capability validation, minimum-host/API checks, and filename-only entrypoints.
- [x] Discover only immediate manifest directories below the deliberate
  `extensions` root and load canonical full DLL paths with restricted Windows
  DLL-search flags.
- [x] Implement initialize/session/project/shutdown lifecycle, transactional
  registration, reverse-order shutdown, duplicate-ID handling, callback error
  containment, and concise diagnostics.
- [x] Preserve bounded opaque JSON state for installed and unknown extensions
  in version-1 `.orev` projects.
- [x] Build one harmless public SDK example without bundling it in the
  production installer.
- [x] Test supported/incompatible APIs, malformed manifests, missing DLL and
  entrypoint, minimum-host mismatch, duplicate IDs, initialization/callback
  failure, unknown capability, state preservation, zero-extension operation,
  and the valid example.
- [x] Document ABI versioning, ownership/lifetimes, capabilities, lifecycle,
  local installation, native trust risk, lack of sandboxing, and future
  out-of-process research.
- [x] Pass clean Release, installer, full CTest, CLI, SDK/example, public-source,
  credential, artifact, local-path, diff, and normal-push gates.

Release-gate evidence (2026-08-16):

- An archive of exact public `HEAD` configured and built from zero into
  `build/windows-x64-phase-d-clean`; application, installer, test executable,
  SDK example, and invalid DLL fixtures were produced.
- CTest passed 1/1. Clean CLI `--help`, `--version`, and fixture analysis exited
  0. The clean desktop remained healthy with zero extensions, the valid example,
  and a missing-DLL manifest.
- The example also configured and built as a standalone CMake project against
  only the public SDK include directory.
- Setup/Portable packaging and SHA-256 generation passed.
- Public-source, credential-shaped value, generated-artifact, local-path,
  protected-file, staged-content, and final-diff scans passed.
- Normal, non-force push completed; local and remote `main` both resolve to
  `1c879ca911d34e530333ba977f94e1141e0f9d92`.
- Private commercialization documents and the pre-existing authentication work
  in `src/main.cpp` and `src/ui/panels/ai_copilot.cpp` remained local and outside
  every public commit.

Gate: Phase D is complete. Legal ownership and proprietary reuse remain
separately **LEGAL REVIEW REQUIRED**. Phase E was not started.

## Phase E — Secure desktop authentication & account integration

Status: `COMPLETE`

Desktop authentication integrated with Supabase Auth and authoritative `/api/me`.

Implementation evidence:

- WorkOS dependencies and endpoints replaced with Supabase Auth (`/auth/v1/token`, `/auth/v1/logout`) and authoritative `GET /api/me` profile synchronization.
- Canonical user identity strictly keyed on `auth.users.id` (UUID). Email is not identity.
- Commercial fail-closed rules enforced: `is_pro_active` trusted only when verified via HTTPS `/api/me` response with `plan == "pro"`.
- `src/auth/account_api.*` implements `SupabaseAccountApi` for direct HTTPS authentication and profile synchronization.
- `src/auth/auth_session.*` and `auth_client.*` implement the session state machine, asynchronous worker threads, startup session restore, and token rotation.
- `src/auth/secure_credentials.*` persists account refresh tokens under `OpenReverse.Account.Session` in Windows Credential Manager, isolated from BYOK AI credentials.
- `src/app/application.*` renders Settings > Account with email/password sign-in, zero password retention, profile info, Community/Pro plan display, renewal and cancellation status, and website account links.
- `tests/auth_tests.cpp` covers UUID validation, password sign-in, session restore, token rotation, revoked sessions, `/api/me` profile verification, commercial fail-closed states, identity mismatch rejection, and Credential Manager persistence.
- `docs/AUTHENTICATION.md` documents the architecture, configuration, credential boundaries, and offline Community behavior.

## Phase F — Minimal cloud backend

Status: `NOT STARTED`

Evidence: no Worker source, D1 migration, API schema, deployment configuration,
or backend tests exist in the current repository set.

Gate: blocked until secure authentication design and legitimate provider
account configuration are available. Provider limits must be rechecked then.

## Phase G — Stripe subscriptions

Status: `NOT STARTED`

Evidence: no Checkout creation, webhook verification, subscription schema,
idempotency store, Customer Portal integration, or Stripe tests exist.

Gate: blocked until Phase F is `DONE` and legitimate Stripe account ownership,
legal/tax readiness, and test credentials exist.

## Phase H — Entitlements and offline license

Status: `NOT STARTED`

Evidence: no authoritative entitlement API, signed license format, public-key
verification, device model, revocation behavior, or offline-grace tests exist.

Gate: blocked until Phases F and G are `DONE` and a server-side signing-key
process is approved.

## Phase I — BYOK AI Pro

Status: `PARTIAL`

Evidence:

- `src/ai/ai_service.*` provides an OpenAI-compatible request path, HTTPS-only
  remote policy, loopback local endpoints, and Windows Credential Manager.
- `src/ui/panels/ai_copilot.*` exposes basic provider setup and current-selection
  context.
- Native Anthropic/Gemini adapters, context privacy toggles, preview, strict
  multi-function budgeting, structured provider errors, and Pro action
  registration do not exist.

Gate: blocked until the entitlement boundary and later commercial security
prerequisites are complete.

## Phase J — Website and commercial UX

Status: `NOT STARTED`

Evidence: current `main` deliberately contains no website source. Historical
deleted website prototypes remain visible under the MIT-licensed Git history and
cannot be treated as new proprietary implementation without review.

Gate: blocked on real product screenshots/features, account configuration, and
legal/product copy review.

## Phase K — Privacy-safe analytics

Status: `NOT STARTED`

Evidence: no desktop telemetry client, consent setting, allow-listed event
schema implementation, ingestion endpoint, or retention policy exists.

Gate: blocked until the backend exists. Reverse-engineering target data remains
prohibited from telemetry.

## Phase L — Updater security

Status: `NOT STARTED`

Evidence: no updater, signed manifest parser/verifier, staging helper, backup,
health check, or rollback tests exist.

Gate: blocked on an approved update-signing key process and completed release
artifacts. Authenticode remains pending an externally obtained certificate.

## Phase M — Release pipeline

Status: `PARTIAL`

Evidence:

- `.github/workflows/windows-release.yml` validates `vx.y.z` against the CMake
  version and requires the tagged commit to be reachable from `origin/main`.
- `scripts/package_release.ps1` produces Setup, Portable, and SHA-256 artifacts.
- `docs/BUILDING.md` documents local and tagged packaging.
- No signed update manifest or Windows code-signing step exists.
- No Git tag or public GitHub release currently exists.

Gate: packaging is ready; signed metadata/code signing remain Phase L/external
certificate work.

## Phase N — Pro distribution

Status: `BLOCKED`

Evidence: no private Pro repository/module, authenticated artifact endpoint,
entitlement check, signed module manifest, or compatibility loader exists.

Blockers: Phase H entitlements, legal ownership review, and private
repository/account configuration.

## Phase O — Launch hardening

Status: `NOT STARTED`

Evidence: no consolidated commercial security audit can pass while auth,
billing, licensing, Pro loading, updater, and analytics are unfinished.

Gate: blocked on Phases E through N.

## Phase P — Commercial test mode

Status: `NOT STARTED`

Evidence: no backend test environment or end-to-end Community-to-cancellation
test fixture exists.

Gate: blocked on a complete test-mode stack and legitimate provider test
accounts/secrets.

## Phase Q — Launch

Status: `BLOCKED`

Evidence: Community has a successful local build/package path, but no public
release, complete Pro product, secure account flow, tested billing, licensing,
or updater exists.

Blockers: every applicable upstream release gate, legal/financial readiness,
real-user testing, and explicit approval to publish or enable live billing.
