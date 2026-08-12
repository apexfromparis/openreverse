# Repository audit

Audit date: 2026-08-12

## Baseline

The audit was performed on `main` after fetching `origin`. The branch matched
`origin/main`; existing local application, analysis, UI, and test changes were
preserved. Before repository cleanup, the Release application, installer,
`OpenReverse.Core` CTest target, `--help`, and `--version` all succeeded.

The repository contains 105 tracked files. CMake downloads pinned versions of
Dear ImGui, Capstone, and nlohmann/json into the build tree. Those generated
dependency trees are not first-party source and were excluded from style
cleanup.

## Inventory and decisions

| Area | Files | Decision |
| --- | --- | --- |
| Build | `CMakeLists.txt`, `CMakePresets.json` | Keep; derive application and installer metadata from the CMake project version. |
| Application | `src/main.cpp`, `src/app/application.*`, `automator.*` | Keep; retain the current composition root and Win32/DirectX shell. Place the headless coordinator here because it consumes `Application`. |
| Core analysis | `src/core/analysis_*`, `cancellation.h`, `data_analyzer.*`, `disassembler.*`, `function_analyzer.*`, `memory_reader.*`, `module_*`, `pattern_scanner.*`, `pe_parser.*`, `process_manager.*`, `string_scanner.*`, `xref_scanner.*` | Keep; these are active analysis and target services. Remove only verified dead members and redundant comments. |
| CLI | `src/core/cli_repl.*` | Move to `src/cli/`; it depends on the application and is not a core analysis service. |
| AI | `src/ai/ai_service.*` | Keep the optional provider client; remove the unused prompt-registry implementation after all callers stopped selecting registry entries. |
| UI framework | `src/ui/ui_manager.*` | Keep; shared theme and compact components are active. |
| UI panels | `src/ui/panels/*.cpp`, `*.h` | Keep active panels. Rename the historically misleading `ida_pro_panel` implementation to `analysis_panel`; remove verified unreachable hex-search state. |
| Vendored editor | `src/ui/vendor/TextEditor.*` | Keep separate from first-party panels; identify it as ImGuiColorTextEdit and retain its MIT notice. |
| Generated font | `src/ui/embedded_font.h` | Keep because it makes the UI build self-contained; mark it generated for GitHub Linguist and document the embedded Roboto font. |
| Installer | `installer/setup_gui.cpp`, `setup.rc.in`, `app.rc.in`, icon | Keep installer source and icon; unify naming/version metadata and repair uninstall behavior. Generated setup executables remain release artifacts only. |
| Tests | `tests/core_tests.cpp` | Keep as one cohesive regression executable; its shared PE fixtures make a split add more plumbing than clarity. |
| Test fixture | `tests/fixtures/crackme/hwid_crackme.cpp` | Keep and build as a small purpose-written PE smoke fixture. It contains no third-party binary. |
| Documentation | `README.md`, `CONTRIBUTING.md`, `SECURITY.md`, `docs/*` | Consolidate around current architecture, building, roadmap, technical debt, and this audit. Remove superseded internal audit/checklist documents. |
| Assets | `assets/logo openreverse.png`, `open_file_driver_support.png` | Move the logo to `assets/branding/`; replace the empty stale image with a current workspace capture under `assets/screenshots/`. |
| CI | `.github/workflows/windows-ci.yml` | Keep one Windows workflow; update artifact names and use the purpose-built PE fixture for smoke tests. |
| Community files | None beyond the workflow | Add focused bug, feature, and pull-request templates. |
| Scripts | `install.ps1`, `scripts/*` | Remove the duplicate root installer with stale URLs. Keep one local CLI installer and one preset-based build wrapper. |
| WinGet | `winget/*` | Remove. No GitHub release currently exists, and the checked-in manifests contain an obsolete repository URL and stale hash. Recreate manifests from a published release artifact when packaging resumes. |

## Confirmed cleanup findings

- `build/`, `build-ui/`, `imgui.ini`, `openreverse_scripts/`, and the root setup
  executable are generated local artifacts. None are tracked; ignore rules need
  to cover arbitrary `build-*` directories.
- `install.ps1` and the WinGet metadata reference an obsolete predecessor
  repository rather than `apexfromparis/openreverse`.
- Historical user-facing product and binary names conflict with the intended
  `OpenReverse` identity.
- CMake is the canonical `2.0.0` version source, but CLI, About, installer text,
  resources, output names, and package metadata duplicate it.
- The installer registers the application itself as an uninstaller, and its
  setup-side uninstall path removes shortcuts and registry data but not the
  installed executable.
- `HexEditorPanel` retains search/copy methods and state that no rendered UI can
  invoke. `DisasmViewPanel` retains an unused syntax flag and a filter that can
  never be edited. `OffsetsPanel::nameInput_` is unused.
- `docs/ARCHITECTURE_AUDIT.md`, `docs/FINAL_HARDENING_PLAN.md`,
  `docs/UI_AUDIT.md`, and the duplicate `docs/TECH_DEBT.md` are internal working
  records superseded by this audit and the maintained technical-debt document.
- The large tracked files are intentional: generated Roboto font data,
  ImGuiColorTextEdit source, and branding media. No compiled binary is tracked.
- Secret and local-path scans found no credential value or personal machine
  path in tracked/pending source. Credential-related matches are API names,
  secure storage code, documentation, or deliberate test-fixture strings.

## Cleanup plan

1. Normalize ignore/attribute rules and third-party notices.
2. Consolidate product/version metadata and make installer/uninstaller behavior
   truthful.
3. Move the CLI and vendored editor to clear ownership directories; rename the
   misleading analysis panel without changing behavior.
4. Remove verified dead state, stale branding, obsolete packaging metadata,
   duplicate docs, and generated local artifacts.
5. Refresh README, build/security/contribution/roadmap documentation and GitHub
   community files against real functionality.
6. Configure and build from a new clean directory, run CTest and CLI/installer
   smoke checks, review every diff, then create logical commits and push
   `main` normally.

## Deferred architecture work

`Application` remains a broad composition root and shared UI state object.
Separating session state and panel-facing query APIs would be a substantial
architecture change, so it remains documented technical debt rather than a
pre-push rewrite. Structure inference remains explicitly labeled, while the
assembly summary now reproduces decoded evidence without invented source-level
semantics.

## Final verification

- Configured with `cmake --preset windows-x64` from an empty `build/` tree.
- Built the Release application, core tests, purpose-built PE fixture, and
  `OpenReverse-2.0.0-Setup.exe` with the checked-in build preset.
- Passed the `OpenReverse.Core` CTest target.
- Passed `--help`, `--version`, offline fixture analysis, and missing-file CLI
  smoke checks with the expected exit codes.
- Verified application and setup Windows version resources as `2.0.0`.
- Verified the setup RCDATA payload has the same SHA-256 as the built
  `OpenReverse.exe`, then opened and closed both application and setup windows
  without performing an installation.
