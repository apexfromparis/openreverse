# Version Intelligence

Version Intelligence is an experimental, review-first workflow for comparing an
older PE binary or PE-backed `.orev` project with the currently open offline
target. Open it from **Analysis > Compare Versions** or **View > Version
Intelligence**.

It does not claim source-level equivalence or calibrated match probabilities.
Numeric similarity values are deterministic heuristic scores. Ambiguity is
preferred to an unjustified automatic choice.

## Workflow

1. Open the newer binary in the normal workspace and wait for analysis.
2. Select an older `.exe`, `.dll`, `.sys`, or PE-backed `.orev` project.
3. Start the comparison. Old-target analysis and matching run as one cancellable
   `AnalysisScheduler` job with real stage progress.
4. Review Functions, Globals, Offsets, Structures, and Signatures.
5. Inspect machine-readable evidence and deterministic change counts.
6. Accept, reject, or reset a mapping. For an ambiguous function, select the
   intended candidate before accepting it.
7. Save the current `.orev` project. Decisions and candidate evidence are
   restored when that project is reopened.

Old project targets must still exist and match their saved SHA-256. The old side
currently supports PE-backed projects and binaries; captured dump projects are
not accepted as the old input yet.

## Matching pipeline

Function instructions are normalized by operand role. Relative control-flow
targets and in-image addresses do not become absolute identity, RIP-relative
displacements are ignored in the code token, small semantic constants and stack
displacements remain distinguishable, and field displacements are retained as
separate provenance.

Candidate generation builds indexes for normalized hashes, ordered instruction
n-grams, ordered block hashes, typed CFG neighborhood tokens,
instruction-count buckets, symbol names, strings, imports, fields, and stable
signature fragments.
Only indexed candidates receive the more expensive multi-signal score. Matching
then proceeds through exact normalized identity, stable signatures, structural
similarity, referenced-data evidence, and caller/callee refinement. Only
already exact or strong callees may strengthen a parent; weak guesses cannot
bootstrap each other. Per-function and total candidate budgets bound expensive
scoring, and signature scan results are reused within one comparison.

Each candidate stores structured evidence for normalized code, CFG, calls,
strings, imports, globals, signatures, runtime boundaries, and matched callees.
The function change summary records instruction, block, edge, and call deltas,
plus added/removed strings, imports, global roles, and field roles. It does not
invent source semantics.

Tiny common wrappers require an additional anchor before becoming strong.
Duplicate normalized candidates remain `Ambiguous`. Results use explicit states:
`Exact`, `StrongCandidate`, `Candidate`, `Ambiguous`, `Removed`, `New`,
`Accepted`, and `Rejected`.

## Migration evidence

- Function offsets follow exact, strong, or explicitly accepted function maps.
- Exports prefer exact export identity before a function-match fallback.
- Imports require matching import identity or a stable typed identifier.
- Globals require access from mapped functions plus compatible section and
  read/write roles.
- Structure fields require the same mapped function, argument provenance,
  access type, width, origin, and normalized instruction role. Numeric proximity
  alone is ignored.
- Signatures scan all bounded executable sections. Zero matches are unmatched;
  multiple matches remain ambiguous. RIP-relative and field relationships are
  decoded at the unique match before a candidate is produced.
- User-defined offsets remain review candidates even when their stable
  identifier is present; they are never silently accepted.

Accepted and rejected decisions are user authority. A rejected stable result
survives recomputation. An accepted function candidate survives only while that
specific candidate still exists, and an accepted migration survives only while
its resolved value is unchanged.

## Verification fixtures

Core regression fixtures cover moved functions, one-instruction changes, CFG
changes, unrelated functions sharing a string, deliberate ambiguity, removed
and new functions, changed global RVAs, changed structure-field displacements,
unique/broken/duplicate signatures, matched-callee evidence, common tiny
wrappers, same-size unrelated functions, reordered instruction evidence,
1,500-function indexed scaling, typed offset migration, cancellation, and
`.orev` decision round-trips. Version Intelligence v1 comparison decisions
remain readable after the algorithm-v2 upgrade.
