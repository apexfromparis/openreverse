# Security policy

## Supported code

OpenReverse does not currently publish stable GitHub releases. Security fixes
are developed against the current `main` branch; older snapshots are not
maintained as supported release lines.

## Reporting a vulnerability

Do not publish exploit details or sensitive samples in a public issue. Use the
repository's private GitHub Security Advisory reporting flow when available. If
private reporting is unavailable, open a minimal public issue requesting a
private maintainer contact without disclosing vulnerability details.

Include the affected commit/version, Windows version, impact, reproduction
steps, and a minimal sanitized proof of concept. Do not send API keys, private
binaries, memory dumps, credentials, personal data, or production secrets.

OpenReverse reads PE files and can inspect processes. Use it only on systems,
binaries, and processes you own or are explicitly authorized to analyze.
