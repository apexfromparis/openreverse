# Community and commercial boundary

Last reviewed: 2026-08-16

This document is the ownership and feature-boundary decision record for
OpenReverse. It must be reviewed before an existing feature is tied to an
entitlement or moved between repositories.

## Capability audit

| Capability | Current location | Already public? | License | Boundary | Notes |
| --- | --- | --- | --- | --- | --- |
| PE and dump parsing | `src/core/pe_parser.*`, `dump_loader.*` | Yes | MIT | Community | Foundational local analysis. |
| Disassembly | `src/core/disassembler.*`, Capstone | Yes | MIT / BSD-3-Clause | Community | Preserve Capstone notices. |
| Functions, CFG, Xrefs, strings, globals, structures, offsets | `src/core`, `src/ui/panels` | Yes | MIT | Community | Existing deterministic and manual workflows stay public. |
| Signatures and typed migration | `src/core/signature_engine.*`, `offset_model.*` | Yes | MIT | Community | Existing ambiguity and review behavior stays public. |
| `.orev` projects | `src/core/project.*`, `analysis_session.*` | Yes | MIT | Community | Project persistence and unknown extension-state preservation stay public. |
| Version Intelligence matching and review | `src/core/version_intelligence.*`, public workspace | Yes | MIT | Community | Basic old/new matching and decisions cannot be moved behind Pro. |
| Community AI/BYOK foundations | `src/ai`, public AI panel | Yes | MIT | Community | Existing local/BYOK behavior remains Community. |
| Versioned extension host and SDK | Phase D public implementation | Intentionally public | MIT | Community | One desktop application; private modules consume the public ABI. |
| Multi-build comparison automation | Not implemented | No | Undetermined | Potential future Pro | New workflow only. **LEGAL REVIEW REQUIRED** before proprietary implementation or reuse. |
| Automatic migration queues and reusable recipes | Not implemented | No | Undetermined | Potential future Pro | Must not remove manual Community migration. **LEGAL REVIEW REQUIRED**. |
| Deeper cross-function structure recovery | Not implemented | No | Undetermined | Potential future Pro | Public primitives remain Community. **LEGAL REVIEW REQUIRED**. |
| Automated reports and multi-target workflows | Not implemented | No | Undetermined | Potential future Pro | Time-saving workflow category, not a Phase D feature. **LEGAL REVIEW REQUIRED**. |
| Team history, collaboration, and cloud sync | Not implemented | No | Undetermined | Potential future service/Pro | Requires separate privacy, security, ownership, and legal review. |

Historical marketplace, account, plugin, and “Pro” demonstrations are public
MIT history, not a production extension foundation and not evidence that their
behavior can be repackaged as newly proprietary. Git author metadata is not a
substitute for an ownership or assignment review.

## Community

Community includes every capability currently published in this MIT repository,
including PE/dump/live inspection, disassembly, CFGs, Xrefs, strings, globals,
field and structure evidence, offsets, signatures, migration, fingerprint
comparison, JSON/C++ export, GUI/CLI surfaces, BYOK, local endpoints, the
OpenAI-compatible AI client, and Windows Credential Manager integration.

Future foundational functionality required to keep the local application useful
also belongs in Community: reliable local project persistence, the stable host
side of the extension API, manual workflows, and a safe plugin mechanism.

## Pro

Pro may contain newly authored proprietary workflow implementations built after
this boundary was established: whole-program Version Intelligence orchestration,
batch comparison/migration, review queues, advanced provenance, reusable
recipes, automation, advanced reports, and deep multi-function AI context.

Pro does not own the public analysis facts or algorithms it consumes. A feature
is not Pro merely because the UI can be gated. Entitlements name explicit
workflows and the server, not the open-source client, remains subscription
authority.

## Shared interface

The public repository owns a narrowly scoped, versioned C ABI, SDK documentation,
and compatibility tests. ABI v1 exposes read-only target/function snapshots,
controlled navigation, command registration, host-rendered text panels, and
extension-owned project state. It reserves but does not grant analysis actions,
AI actions, filesystem, network, process-memory, or general project-write
capabilities. It does not expose `Application`, STL containers, Dear ImGui
internals, allocator ownership, or arbitrary process memory.

A future private Pro repository should consume that API without copying or
forking the Community desktop. Private module distribution and signing do not
exist yet and require their own security, entitlement, and legal gates.

## Historical public code

Reachable Git history contains MIT-licensed prototypes for pricing/auth UI,
account and subscription commands, marketplace/plugin claims, and decompiler
demonstrations. Deletion from the current tree did not revoke the MIT license on
published copies. Reuse in a private product requires an explicit provenance and
ownership decision; rebranding an old public prototype does not make it newly
proprietary.

## Third-party and ownership review

Current notices identify Dear ImGui and ImGuiColorTextEdit (MIT), Capstone (BSD
3-Clause), nlohmann/json (MIT), and Roboto (Apache 2.0). Preserve all required
notices in every distribution containing those components.

The current Git history shows one author identity, but that is not conclusive
legal evidence of copyright ownership or assignment. Before commercial launch:

- verify authorship and provenance of first-party source and historical web
  assets;
- confirm trademark/domain ownership for OpenReverse;
- choose and publish a contribution policy (CLA or DCO as appropriate);
- have counsel review dual licensing, contributor terms, privacy, consumer
  subscription terms, VAT/tax responsibilities, and third-party notices.

External contributor code must not be copied into `openreverse-pro` without a
license and ownership review. Unresolved items remain Community or are replaced
with newly authored code behind the public extension boundary.

## Change checklist

Before classifying a capability as Pro, record:

1. the exact public and historical paths searched;
2. the commit where the new implementation originated;
3. all authors and applicable contribution terms;
4. third-party code and license obligations;
5. the Community workflow that remains useful;
6. the new time-saving Pro workflow and entitlement ID;
7. the tests proving Community operates without Pro;
8. legal-review status when ownership is not unambiguous.
