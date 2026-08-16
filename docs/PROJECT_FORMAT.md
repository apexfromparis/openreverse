# OpenReverse project format

OpenReverse projects use the `.orev` extension. Version 1 is a bounded JSON
document that stores analysis state and a reference to the target; it does not
embed the target binary or execute content while loading.

## Root and identity

The required root fields are:

```json
{
  "format": "openreverse-project",
  "version": 1,
  "target": {},
  "analysis": {},
  "user": {},
  "ui": {},
  "integrity": {}
}
```

`target` records its kind, path, SHA-256, architecture, image base, module size,
selected minidump module, and `ModuleIdentity` metadata. Addresses intended to
survive rebasing are stored as RVAs. The target file remains external.

`analysis` stores typed offsets, relationship-aware signatures, and inferred
structure evidence. `user` stores function names/comments, bookmarks, accepted
or edited structures, migration decisions, and project settings. `ui` stores a
small workspace/panel selection and current RVA.

Version 1 also permits an additive optional `version_intelligence` section.
Projects written before that section existed remain valid. When present, it
stores the old/new SHA-256 identities, analysis algorithm version, function
candidates, structured evidence, deterministic change summaries, migration
candidates, new-function RVAs, and explicit user decisions. It stores no binary
bytes or executable content.

Version 1 also permits an additive optional `extensions` object keyed by the
canonical extension ID. Each value is an extension-owned JSON object. The core
does not interpret the object's schema, but validates and canonicalizes it,
includes it in the integrity digest, and preserves it even when the owning
extension is not installed. Older version-1 projects without this root member
remain valid.

## Integrity and limits

Before publication, OpenReverse serializes the document without `integrity`,
computes SHA-256 over its canonical compact JSON representation, and adds that
digest to the root. Loading recomputes and compares the digest before decoding
the typed state. This detects accidental truncation or modification; it is not
a digital signature and does not establish who authored a project.

Projects are limited to 16 MiB. Collections, strings, structures, fields,
settings, and imported offset/signature records have additional bounds. Invalid
types, malformed JSON, missing sections, failed integrity, and unsupported
future versions return explicit errors instead of partial state.

Version Intelligence functions, candidates, migrations, evidence, names, and
change lists are independently bounded. An unsupported comparison algorithm
version is rejected even when the surrounding project format is valid.

Extension state is limited to 128 IDs and 256 KiB per object, with a maximum
depth of 16 and 10,000 JSON nodes. IDs and object keys/strings are bounded,
floating-point values must be finite, and the root value must be an object.
State is data only and is never loaded as code.

## Save and load behavior

Saves use a unique sibling staging file, flush it with `FlushFileBuffers`, then
publish with `ReplaceFileW` or `MoveFileExW`. A failed save leaves the previous
project in place and removes the staging file where possible.

On load, OpenReverse hashes the referenced target:

- Matching SHA-256: restore target-bound state.
- Missing/unreadable target: ask the user to locate it or cancel.
- Different SHA-256: locate the original, cancel, or open the changed target
  without restoring target-bound annotations. The changed-target path requires
  Save As before it can replace a project.

## Version migration policy

The reader validates the stored envelope and integrity using the stored version
before typed decoding. `MigrateProjectDocument` is the single sequential JSON
migration boundary for future older versions. No pre-v1 `.orev` schema was ever
published, so version 1 currently has no predecessor migration. Unknown future
versions and older versions without a registered safe migration are rejected;
OpenReverse never guesses a conversion.
