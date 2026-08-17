# Confirmed remaining analysis work

Verified after the 2026-08-17 technical-hardening pass. The canonical product
version remains `2.0.0` from the top-level CMake project.

## P0 correctness

No release-blocking static-analysis execution or parser correctness issue is
known from the automated suite. New malformed PE/dump cases should be minimized
and added to the bounded mutation fixtures when discovered.

## P1 analysis quality

- Extend optional DIA support only where controlled fixtures justify additional
  source/type relationships; define symbol-server and privacy policy first.
- Preserve the current conservative predecessor merging while researching
  bounded indirect targets, tail calls, pointer chains, and deeper
  interprocedural evidence. Do not label this general alias analysis.
- Feed validated PE relocation-directory evidence into signature generation.
- Extend Version Intelligence to old dump projects and measured indirect-call
  neighborhoods without allowing weak matches to bootstrap each other.
- Run `OpenReverseValidation` against a documented, legally redistributable
  representative corpus and retain only aggregate regression baselines.

## P2 architecture and performance

- Migrate remaining compatibility Xref/string panel caches to direct
  `AnalysisDatabase` queries.
- Extract target lifecycle or navigation from `Application` only when ownership
  and lifetime tests can move with the boundary.
- Use corpus stage timings to decide whether shared decoding, multi-pattern
  signature matching, or additional database indexes are justified.

## P3 product and validation

- Manually verify the graphical CFG across DPI/window sizes and large cyclic
  functions, then consider better routing/minimap behavior above the current
  512-node rendering budget.
- Add non-pixel workflow tests where desktop target switching or project
  lifecycle logic can be isolated from native dialogs.
- Exercise the installer through install, launch, repair/upgrade, and uninstall
  on a clean Windows VM before the first public beta.
