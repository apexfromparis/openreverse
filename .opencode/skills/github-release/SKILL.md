---
name: github-release
description: Use when managing Git branches, commits, pull requests, CI, releases, or publishing Powerfull IDA to GitHub.
---

# GitHub Workflow

- Inspect status and diff before staging; never include binaries, secrets, tokens, or local settings.
- Keep commits small and describe one coherent change in imperative language.
- Use feature branches for non-trivial work and keep `main` buildable.
- Add CI for MSVC compilation, warning checks, tests, and artifact publication where appropriate.
- Treat release artifacts as generated outputs; document reproducible build commands.
- Review permissions and repository visibility before publishing anything.
- Use `gh` for GitHub operations and report the resulting URL or failed check clearly.
