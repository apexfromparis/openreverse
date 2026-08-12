# Offset and structure analysis

OpenReverse treats an offset as a typed relationship with provenance, not as an
unqualified integer.

## Typed records

`OffsetRecord` supports global RVA, structure field, function RVA, import RVA,
export RVA, pattern match, and user-defined records. Each record can retain its
stable ID, module/section, source function and instruction, access type, operand
width, qualitative evidence, raw evidence score, and provenance messages.

Module association uses SHA-256, PE timestamp, image size, image base, and
optional version/PDB metadata. A filename alone is not an identity.

## Globals

For a resolved RIP-relative memory operand:

```text
target = instruction end address + signed displacement
```

The target must lie in a valid non-executable module section. OpenReverse keeps
the VA/RVA, section, read/write/address counts, source functions, operand widths,
access sites, and contributing Xrefs. Classification stays limited to evidence
available from the section and Xref kind.

## Fields and structures

A memory operand such as `[rcx+0x1a8]` retains:

- base and index registers, scale, and signed displacement
- operand index and width
- read, write, read/write, or address access
- source instruction and containing function
- register origin and Windows x64 argument index when observed

Within a basic block, straightforward register copies and `LEA` adjustments are
propagated. RCX, RDX, R8, and R9 begin as arguments 1–4. Stack locals are not
treated as object fields, and ambiguous arithmetic stops propagation.

Structures group compatible observations by function and argument/root context.
They retain all observing functions, base registers, widths, reads/writes, and
access sites. A candidate is not a recovered C++ type.

## Signatures

Patterns store every byte as `{value, wildcard}`. Literal `FF` is therefore not
confused with a wildcard. Candidate generation operates on contiguous decoded
instructions and masks unstable relative immediates, RIP displacements,
in-module pointers, and supplied relocations.

A signature relationship can resolve:

- the match address
- a function RVA at an instruction offset
- a RIP-relative operand target
- a structure-field displacement

Uniqueness defaults to executable sections. Status is explicit: unique,
ambiguous, not found, or invalid.

## Import, export, and migration

Offset projects are bounded JSON documents parsed with nlohmann/json. They are
never compiled or executed. C++ export sanitizes identifiers and disambiguates
duplicates.

The Migration tab compares imported signatures with the current static image.
It rescans only when the imported project or current database revision changes.
A unique signature plus a valid relationship yields a review candidate;
ambiguous matches are retained for review and are never auto-accepted.

Function fingerprint comparison normalizes instruction and operand classes and
adds CFG shape, strings, call count, and instruction count. Its numeric result is
an explicit similarity score, not a statistical probability.
