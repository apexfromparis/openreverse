---
name: testing-debugging
description: Use when adding tests, reproducing crashes, debugging native code, validating binary parsers, or checking regressions in Powerfull IDA.
---

# Testing And Debugging

- Test parsers with valid, truncated, oversized, corrupted, and adversarial fixtures.
- Keep engine tests headless and deterministic; do not require the Win32 window to test analysis.
- Add regression fixtures for every crash or incorrect decode.
- Exercise plugin load, ABI rejection, unload, cancellation, and failure paths.
- Use debug builds, compiler warnings, Application Verifier, and memory diagnostics when available.
- Verify UI behavior at startup, resize, empty state, file-open failure, and analysis cancellation.
- Report the exact command, environment, and result for every verification run.
