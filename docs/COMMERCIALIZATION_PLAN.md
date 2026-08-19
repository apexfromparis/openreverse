# OpenReverse commercialization plan

Status: product-foundation baseline

Last verified: 2026-08-16

This plan is based on the current `main` tree, its reachable Git history, the
MIT license, third-party notices, the Release build, and the official service
limits linked below. It does not classify planned or mocked behavior as a
shipped product capability.

## 1. Current Community capabilities

The current Community application is a useful native Windows reverse-
engineering workspace. The public implementation includes:

- PE32/PE32+ parsing, raw-file/RVA-mapped address spaces, mapped dumps, raw
  snapshots, and captured minidump-module analysis;
- read-only live-process attachment, process/module enumeration, memory maps,
  module exports, and memory dumping where Windows grants access;
- x86/x64 Capstone disassembly, x64 `.pdata` function boundaries, bounded CFGs,
  direct-call discovery, and heuristic fallbacks;
- typed operand Xrefs, string scanning, RIP-relative globals, conservative
  field evidence, inferred structure candidates, and indexed navigation;
- hex/data views, bookmarks, pattern scanning, PE inspection, strings,
  functions, CFG presentation, offsets, signatures, and migration review;
- typed offsets, SHA-256 module identity, JSON import/export, C++ header export,
  signature generation, uniqueness evaluation, and explicit ambiguous/not-found
  outcomes;
- a public function-fingerprint comparison API with reviewable evidence;
- GUI and CLI surfaces, a Windows installer, deterministic core tests, and
  Windows CI;
- optional OpenAI-compatible AI requests, local endpoints, BYOK, HTTPS
  enforcement for non-loopback endpoints, and API-key storage in Windows
  Credential Manager.

Important limitations are part of the product truth:

- no durable `.orev` project containing names, comments, bookmarks, accepted
  migrations, and analysis snapshots;
- no whole-program old/new comparison workspace despite the public fingerprint
  primitives;
- no concrete PDB/DIA provider, spatial CFG layout, executable script runtime,
  plugin API, extension loader, account system, updater, or published release;
- the existing AI service is primarily OpenAI-compatible and is not yet a
  clean native multi-provider abstraction;
- heuristic fields, structures, function recovery, and AI output remain
  suggestions, not authoritative facts.

## 2. Current features that can support Pro workflows

The following public primitives can remain Community while powering new private
workflow implementations:

| Public primitive | Potential new Pro workflow |
| --- | --- |
| Function fingerprints and explicit ambiguity | Whole-program Version Intelligence review queue |
| CFG, Xrefs, calls, strings, globals, and fields | Multi-signal function matching with evidence drill-down |
| Signature generation/evaluation | Batch signature health, migration, and replacement proposals |
| Typed offsets and module identity | Versioned offset migration and provenance history |
| Structure candidates and access sites | Cross-function structure evidence aggregation |
| Canonical analysis database | Batch recipes, advanced reports, and contextual AI bundles |
| JSON/C++ export | Versioned export templates and CI-oriented report packs |
| BYOK request path | Deep-context actions paid for by the user's provider key |

Pro value must be the time-saving workflow around these primitives: two-target
coordination, candidate ranking, review state, batch execution, reusable
recipes, evidence-preserving reports, and migration history. The public
algorithm or Community button must not be relabeled as proprietary.

## 3. Features that cannot simply be moved to Pro

The following are already public under MIT and remain Community baselines:

- all current PE/dump/live analysis, disassembly, CFG, Xrefs, strings, globals,
  fields, structures, offsets, patterns, signatures, JSON/C++ export, and UI;
- `binary_diff.*`, including fingerprint construction, similarity scoring,
  set comparison, and explicit unique/ambiguous results;
- current signature and offset migration code and its Migration UI;
- the current AI client, BYOK support, local endpoints, OpenAI-compatible
  providers, Credential Manager storage, and current analysis-context actions;
- installer/CLI/editor functionality and any other code already committed under
  the repository's MIT license.

Reachable history also contains previously public MIT-licensed prototypes for a
pricing page, Supabase-style auth modal, decompiler demonstration, account/tier
commands, marketplace commands, and plugin installation claims. Those copies
remain MIT-licensed even if later deleted. They were mock-oriented and are not
evidence of a working commercial system, but they must not be presented as new
proprietary implementation without a clean ownership and provenance review.

`git shortlog` currently shows one author identity, but Git metadata alone is
not proof of copyright ownership, employment assignment, trademark rights, or
the absence of copied code. Before accepting outside contributions, introduce a
documented contribution policy and decide whether a CLA or Developer Certificate
of Origin is appropriate. Legal counsel must review any plan to reuse historical
web/auth code privately or dual-license contributor work.

Third-party constraints currently identified:

- Dear ImGui and ImGuiColorTextEdit: MIT;
- Capstone: BSD 3-Clause;
- nlohmann/json: MIT;
- embedded Roboto: Apache 2.0.

Their notices must remain in Community distributions and any Pro distribution
that contains them. See [COMMERCIAL_BOUNDARY.md](COMMERCIAL_BOUNDARY.md) for the
maintained decision record.

## 4. Recommended Community/Pro boundary

Community remains the complete local manual workstation. It keeps target
opening, analysis facts, navigation, manual signature/offset workflows, local
projects when implemented, plugins, BYOK, local models, and basic contextual AI.

Pro is a separately delivered extension containing new advanced workflows:

- Version Intelligence workspace for old/new projects and binaries;
- multi-signal function/global/field candidate mapping with uncertainty queues;
- batch signature and offset migration with explicit review/accept/reject state;
- advanced cross-function structure recovery and provenance;
- multi-function and batch context construction, reusable recipes, advanced
  reports, and automation;
- Pro-specific extension capabilities that do not remove Community plugin use.

Deterministic facts and AI proposals use separate models and presentation.
Every migration candidate exposes its contributing evidence. Ambiguity always
requires user review. No startup paywall, binary-content upload, or hosted AI is
part of V1.

## 5. Recommended repository separation

Use three repositories, not separate desktop forks:

1. `openreverse` (public, MIT): Community desktop, deterministic core,
   versioned extension C headers, a harmless example extension, SDK docs, and
   compatibility tests.
2. `openreverse-pro` (private): the proprietary extension, Pro workflow tests,
   packaging metadata, and private build pipeline. It consumes published
   Community SDK artifacts and never copies the full desktop source.
3. `openreverse-cloud` (private): one small monorepo for the website, account
   API, D1 migrations, Stripe webhooks, license issuer, and infrastructure
   configuration.

The website may be deployed from `openreverse-cloud/apps/web`; a fourth
repository is unnecessary until ownership or deployment constraints demand it.

## 6. Extension API requirements

Use a versioned C ABI rather than exposing STL types, Dear ImGui internals, or
`Application` across a DLL boundary. A C ABI makes compiler/runtime ownership,
structure size, and compatibility checks explicit.

Required V1 contracts:

- host ABI major/minor, structure sizes, capability bits, and minimum desktop
  version;
- module metadata: immutable module ID, version, publisher, build ID, requested
  capabilities, and signed manifest digest;
- host-owned alloc/free callbacks and UTF-8 length-delimited data;
- read-only snapshot queries for modules, functions, instructions, CFGs, Xrefs,
  strings, globals, fields, structures, signatures, and project metadata;
- action registration for navigation, analysis jobs, export providers, AI
  actions, commands, and approved UI panels;
- opaque handles with documented lifetimes; no raw internal pointers;
- cancellation, bounded result sizes, thread-affinity rules, and structured
  errors;
- capability-scoped write operations for names, comments, bookmarks, accepted
  migrations, and generated reports;
- compatibility tests covering older host/newer module and newer host/older
  module combinations.

Discovery must use an explicit installed-module registry or signed manifest,
not automatic loading of every DLL in a writable directory. The loader checks
publisher trust, file digest, module signature, ABI version, and entitlement
before `LoadLibraryEx` with restricted search flags. An incompatible or
untrusted module is reported without crashing or loading code. An out-of-process
model remains the preferred future boundary for third-party untrusted plugins;
the in-process V1 boundary is for trusted OpenReverse modules.

## 7. Minimal backend requirements

Expose one versioned HTTPS API:

- `GET /v1/me`
- `GET /v1/entitlements`
- `POST /v1/devices/activate`
- `GET /v1/devices`
- `DELETE /v1/devices/{id}`
- `POST /v1/licenses/issue`
- `POST /v1/billing/checkout`
- `POST /v1/billing/portal`
- `POST /v1/webhooks/stripe`
- a narrowly scoped auth callback/session exchange as required by the selected
  identity provider.

Use Supabase Auth for identity (email/password and sessions), a backend service
for API code, PostgreSQL/D1 for application data, and authenticated Pro-module
artifacts. Keep identity-provider user IDs as external UUIDs. Do not copy
profiles or tokens that are not required.

Minimal tables are `users`, `subscriptions`, `entitlements`, `devices`,
`licenses`, `events`, and `processed_webhooks`. Add unique constraints for
provider IDs, device IDs per user, and Stripe event IDs. Store no target binary,
disassembly, strings, pseudocode, provider key, or card data.

## 8. Billing architecture

The desktop opens a server-created Stripe Checkout Session in the browser.
Stripe hosts payment collection. The backend alone owns Stripe secret keys and
webhook secrets. A success redirect is informational and never grants Pro.

The webhook endpoint verifies the Stripe signature against the exact raw body,
deduplicates by event ID, and transactionally updates subscription state and
explicit entitlements. Handle at least:

- `checkout.session.completed`;
- `customer.subscription.created`, `.updated`, and `.deleted`;
- `invoice.paid` and `invoice.payment_failed`.

Create Customer Portal sessions server-side. Store Stripe customer,
subscription, price, status, and period-end identifiers. Map backend-configured
price IDs to product/entitlement sets; never hardcode a final euro price or
trust client-supplied plan names.

## 9. License and entitlement architecture

Online authority is `GET /v1/me`; the desktop cache is not billing authority.
Return explicit entitlement identifiers such as:

- `version_intelligence`
- `advanced_diff`
- `signature_migration`
- `offset_migration`
- `advanced_structures`
- `deep_context`
- `batch_analysis`
- `advanced_reports`

For offline use, issue a compact JWS signed with ES256 using a maintained JOSE
implementation server-side and Windows CNG verification desktop-side. Pin the
expected algorithm, key ID, license schema version, issuer, and audience. The
payload contains user ID, plan, exact entitlements, issued/expiry times, device
ID, license version, and optional offline-grace end. The signing private key
exists only as a server secret; the desktop contains public verification keys.

Use a short online token lifetime and a user-friendly offline license window
(initial hypothesis: seven days, to validate with users). Expiry disables only
Pro workflows and never damages Community data. Device IDs are random
installation UUIDs stored securely, not aggressive hardware fingerprints.

## 10. BYOK architecture

Refactor without removing the existing Community AI client:

- `IAIProvider`: provider-specific request/response, capability, and error
  normalization;
- `AIProviderRegistry`: built-in OpenAI, OpenRouter, Anthropic, Gemini,
  OpenAI-compatible, and local adapters;
- `ModelRegistry`: user-configurable model metadata, not a stale hardcoded
  pricing catalog;
- `AIContextEngine`: deterministic selection-to-context assembly with budgets;
- `AIActionRegistry`: Community and extension-registered structured actions.

Credentials stay in Windows Credential Manager, namespaced by provider and
endpoint. Never log keys, authorization headers, refresh tokens, request bodies,
or provider responses by default. Reject non-HTTPS remote endpoints; permit
plain HTTP only for exact loopback hosts.

Add per-category privacy controls for disassembly, strings, pseudocode, symbols,
and structure evidence plus “Preview context before sending.” Send only the
selected bounded context, never complete binaries. Pro buys context engineering
and workflows; provider token charges remain the user's responsibility.

## 11. Security threat model

| Asset / boundary | Primary threats | Required controls |
| --- | --- | --- |
| Browser/desktop sign-in | code interception, CSRF, token leakage | authorization code with PKCE or device flow, high-entropy state/verifier, loopback callback, single-use short-lived code |
| Desktop tokens | local theft, logs, custom-URI disclosure | Windows Credential Manager, never display/log tokens, refresh-token rotation, logout deletion |
| API | replay, abuse, broken object authorization | validated issuer/audience/signature, per-user authorization, rate limits, idempotency, structured audit events |
| Stripe webhook | forged/replayed events | raw-body signature verification, timestamp tolerance, unique event ID, transactional updates |
| Entitlements | client tampering, stale subscription | server authority, explicit grants, short cache TTL, signed offline JWS |
| Offline license | forgery, rollback, wrong device | ES256 verification, pinned algorithm/key, expiry/device checks, key rotation, bounded grace |
| Device activation | slot exhaustion, tracking | random install ID, user-visible devices, limits, self-service deactivation, rate limits |
| Pro module | DLL planting, downgrade, ABI crash | authenticated install, signed manifest/digest, publisher allow-list, ABI/version checks, restricted DLL search |
| Pro download | URL sharing, replacement | short-lived authenticated URL, SHA-256, signed manifest, TLS, version pinning |
| BYOK keys/context | credential or target leakage | Credential Manager, HTTPS policy, preview/privacy controls, secret redaction, no analytics payloads |
| Update channel | supply-chain substitution | protected release workflow, signed release metadata, digest verification, Windows code signing, rollback |
| Analytics | target-data exfiltration | allow-listed event schema, no free-form target metadata, opt-out, retention limit |

Current local-worktree blocker: uncommitted code registers an `openreverse://`
handler, accepts a value named `token` through `WM_COPYDATA`, saves it as an AI
provider key, and displays it in a message box. That design leaks bearer material
through process command lines, URI history, IPC, and the UI. It must not ship.
Replace it in Phase C with PKCE/device authorization; do not pass access or
refresh tokens through a custom URI.

## 12. Launch funnel

Measure this sequence without requiring a Community account:

1. landing-page visitor;
2. Community download;
3. application installed or portable first run;
4. first binary opened;
5. first successful deterministic analysis;
6. return in a later week;
7. contextual Pro workflow viewed;
8. account sign-in;
9. trial started;
10. Checkout started;
11. subscription activated by webhook;
12. paid retention or cancellation.

The first launch exposes Open Binary, Open Dump, Attach Process, and Open
Project. Account creation is never required for Community. A seven-day
server-enforced Pro trial without a card is the initial hypothesis; do not ship
it until the first Pro workflow is sufficiently reliable to demonstrate value.

## 13. Metrics

Use allow-listed events only: `app_installed`, `binary_opened`,
`analysis_completed`, `project_saved`, `ai_used`, `pro_feature_viewed`,
`pricing_opened`, `trial_started`, `checkout_started`,
`subscription_started`, and `subscription_cancelled`.

Allowed metadata is product version, OS major version, event schema version,
coarse duration bucket, success/failure category, and feature ID. Do not send
paths, hashes, addresses, binary names, bytes, strings, symbols, disassembly,
pseudocode, prompts, responses, or free-form errors.

Core product measures are download-to-activation, first-analysis success,
weekly retention, advanced-workflow discovery, trial conversion, free-to-paid
conversion, MRR, gross revenue retention, and churn. Page views, stars, and
community size are supporting signals, not product success metrics. Desktop
telemetry is documented, opt-out, and off until consent is established.

## 14. Estimated infrastructure components

| Component | Initial choice | Purpose |
| --- | --- | --- |
| Public repository/releases | GitHub | source, CI, Setup/Portable/checksums |
| Website/docs | Cloudflare Pages static assets | Home, Product, Pricing, Download, Docs |
| Account/API | Website / API backend | auth integration, entitlements, billing endpoints |
| Database | PostgreSQL / Supabase | users, subscriptions, entitlements, devices, events |
| Pro artifact storage | Cloudflare R2 / S3 | signed module packages |
| Identity | Supabase Auth | email/password, sessions, and OAuth |
| Billing | Stripe Checkout, Billing, Customer Portal | cards and subscriptions |
| License signing | Backend secret + established JOSE/WebCrypto | ES256 offline entitlements |
| Product analytics | allow-listed API events in DB initially | funnel without target data |
| Secrets | Encrypted secrets / provider dashboards | Stripe, Supabase keys, signing key |

Do not add an always-on VPS, Redis, queue, Kubernetes, hosted inference,
separate analytics vendor, or custom admin dashboard in V1.

## 15. Components that can begin on free tiers

Limits below were checked against official pages on 2026-08-16 and must be
rechecked immediately before launch:

- [Cloudflare Pages](https://developers.cloudflare.com/pages/functions/pricing/):
  static asset requests are free and unlimited; dynamic functions share the
  Workers quota.
- [Cloudflare Workers](https://developers.cloudflare.com/workers/platform/pricing/):
  Free includes 100,000 requests/day and 10 ms CPU per invocation; the paid
  plan currently starts at USD 5/month.
- [Cloudflare D1](https://developers.cloudflare.com/d1/platform/pricing/):
  Free includes 5 million rows read/day, 100,000 rows written/day, and 5 GB
  total storage; D1 has no egress fee.
- [Cloudflare R2](https://developers.cloudflare.com/r2/pricing/): Standard
  storage includes 10 GB-month, 1 million Class A and 10 million Class B
  operations/month, with direct egress free.
- [Supabase Auth](https://supabase.com/pricing): user management free tier
  includes generous monthly active users for standard auth and database access.
- [GitHub Actions](https://docs.github.com/en/billing/concepts/product-billing/github-actions):
  standard GitHub-hosted runners are free for public repositories.
- [GitHub Releases](https://docs.github.com/en/repositories/releasing-projects-on-github/about-releases):
  each asset must remain below 2 GiB; GitHub documents no total release-size or
  bandwidth limit.
- [Stripe standard pricing](https://stripe.com/fr/pricing): no setup or monthly
  fee; standard EEA card processing is currently 1.5% + EUR 0.25, while Billing
  pay-as-you-go is listed at 0.7% of Billing volume. Checkout is hosted. These
  transaction costs begin only with revenue.

Free-tier availability is not an SLA. Add budget alerts and hard usage limits.
The domain name and a reputable Windows code-signing certificate are expected
fixed launch costs and require vendor quotes rather than invented estimates.

## 16. Components that eventually create variable costs

- Stripe card and Billing fees per successful paid subscription, plus disputes,
  refunds, tax, and currency costs where applicable;
- Server requests/CPU, database rows/storage, and storage/operations after free
  allowances;
- Supabase only beyond its included users;
- private-repository CI minutes/artifacts for `openreverse-pro` and
  `openreverse-cloud` beyond the account allowance;
- transactional email if managed identity allowances are exceeded;
- domain renewal, Windows code signing, support, legal/accounting, and tax
  compliance;
- optional crash reporting or observability only after measured need.

BYOK AI inference remains a direct user-to-provider cost and contributes zero
OpenReverse inference expense in V1.

## 17. Exact implementation order

### Phase A — product foundation

1. Keep the current Community feature inventory and commercial boundary in
   version control; re-audit before every entitlement change.
2. Remove or quarantine fake/unverified commercial claims from future product
   surfaces; never advertise hosted AI, marketplace, or cloud features that do
   not exist.
3. Define `.orev` schema v1 for target identity, user names/comments,
   bookmarks, structures, accepted migrations, and deterministic provenance.
4. Implement atomic `.orev` save (temporary sibling, flush, replace), bounded
   parsing, version migration, target-hash mismatch warning, and recovery tests.
5. Build a two-target Version Intelligence model above the existing public
   fingerprint/signature primitives: evidence records, thresholds, explicit
   ambiguity, review states, and deterministic fixtures.
6. Add old/new workspace UI only after the core comparison API passes fixtures;
   keep manual Community migration intact.
7. Publish Community release automation producing exactly
   `OpenReverse-x.y.z-Setup.exe`, `OpenReverse-x.y.z-Portable.zip`, and
   `SHA256SUMS.txt` from a version-matched protected tag.
8. Define signed update-manifest and rollback design. Do not enable automatic
   update installation until release signing, integrity verification, and
   failure rollback have automated tests.
9. Run clean Release build, CTest, CLI smoke tests, installer payload checksum,
   and portable-package smoke tests.

Phase A exit criteria: reliable project round-trip, reviewable version matching
on representative fixtures, a reproducible Community release, no regression in
current Community workflows, and no unresolved credential leak in release code.

### Phase B — extension architecture

10. Specify the versioned C ABI and threat model.
11. Build a public no-secret example extension and compatibility harness.
12. Implement explicit trusted-module installation/discovery and failure UI.
13. Create `openreverse-pro` privately and implement one thin Version
    Intelligence workflow against the SDK; do not duplicate Community.

### Phase C — account system

14. Integrate Supabase Auth and database tables (`public.profiles`, `public.subscriptions`).
15. Implement desktop email/password sign-in, session restore, Credential Manager storage, refresh, logout, and `/api/me`.
16. Add random installation IDs and user-managed device activation.

### Phase D — billing

17. Configure Stripe test products/prices; keep price IDs server-configured.
18. Implement hosted Checkout, verified/idempotent webhooks, subscription state,
    explicit entitlements, failed-payment handling, and Customer Portal.
19. Test lifecycle events with Stripe test clocks/CLI and database assertions.

### Phase E — licensing

20. Implement ES256 JWS issuance, public-key verification, key rotation,
    device binding, offline grace, and expiry behavior.
21. Test invalid signatures, wrong devices, clock boundaries, cancellation,
    restoration, API outage, and incompatible Pro modules.

### Phase F — BYOK Pro AI

22. Introduce provider/context/action abstractions while preserving Community
    AI behavior and Credential Manager data.
23. Add native provider adapters, privacy toggles, context preview, bounded
    multi-function context, structured outputs, and normalized provider errors.
24. Register only genuinely new deep-context/batch actions from Pro.

### Phase G — website

25. Build the small static site with real application screenshots and truthful
    Community/Pro comparison; mark unreleased Pro workflows as preview only.
26. Add Download, Docs, Account, Supabase Auth integration, server-configured pricing,
    Checkout links, BYOK cost disclosure, privacy, and terms.

### Phase H — analytics

27. Publish the event schema/privacy document and opt-out control.
28. Add allow-listed website/API/desktop events and conversion queries without
    target data or arbitrary metadata.

### Phase I — launch

29. Sign and publish Community Setup/Portable/checksums; validate update staging.
30. Invite a small no-card Pro trial cohort, observe migration accuracy and
    workflow completion, then enable paid Checkout.
31. Review activation, retention, conversion, support load, gross margin, and
    churn before changing prices, trials, hosting, or feature boundaries.

No Phase B work begins until the Phase A exit criteria and legal boundary review
are complete.
