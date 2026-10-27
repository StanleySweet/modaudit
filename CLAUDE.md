# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Start here

Read `.docs/context.md` first: dense project context, hard rules, verdicts and references. Full spec: `.docs/design.md`. Decisions (ADRs, never rewritten, only superseded): `.docs/decision/`. Current phase plan: `.docs/plan/01-audit-cli.md`. Task ledger: `.superpowers/sdd/01-audit-cli/progress.md` (records per-task rulings; append when finishing a plan task).

`0ad.wiki/`, `.ref/` and `.superpowers/` are gitignored reference material, not project code.

## Commands

```sh
go build ./...                       # build
go test ./...                        # full suite
go test ./internal/audit -run TestVerdictMatrix   # single test
go vet ./...
go test ./internal/audit -run '^$' -fuzz FuzzRunOnArbitraryBytes -fuzztime 20s   # fuzz
go test ./internal/report -run TestGoldenRepackage -update   # regenerate testdata/golden
go run ./cmd/modaudit audit --zip mod.zip --bundle bundle.json
```

Local config: copy `config.toml.example` to `config.toml` (gitignored). Secrets are referenced via file or command, never inlined.

## Architecture

Go module `github.com/stan/modaudit`. Phase 1 is the offline, deterministic audit CLI: no network, no signing, no LLM calls in the binary. Sole non-stdlib dependency: `github.com/BurntSushi/toml`.

- `internal/config`: loads `config.toml`; `Limits` holds the hard caps (entries, uncompressed bytes, ratio, per-file size, script bytes, bundle budget).
- `internal/audit`: `Run` (`scan.go`) is the pipeline:
  1. `Inventory` streams the zip once into `Scan.Entries` (hash, size, `Kind`). Content is never retained. Cap violations set `Scan.Aborted` and short-circuit to `REFUSE`.
  2. `LoadScriptBodies` re-reads only `.js` entries, capped at `MaxScriptBytes`.
  3. Fixed rule order: `rulesArchive`, `rulesLayout`, `rulesModJSON`, `rulesScript`, `rulesAsset`, `rulesPackaging`. Each file `rules_*.go` appends `Finding`s via `Scan.AddFinding(code, severity, file, detail)`.
  4. Findings sorted deterministically; `VerdictOf` maps them: any blocker or abort → `REFUSE`; `BUNDLE_BUDGET_EXCEEDED` → `NEEDS_HUMAN`; `PackagingIssues` → `REPACKAGE`; else `SIGN`.
- `internal/report`: builds and serialises the JSON report from a `Scan`, plus `Bullets` for comment drafts generated from rule codes.
- `internal/bundle`: changed scripts (vs a baseline manifest) for LLM review; over cap returns `ErrBudget`, never truncates.
- `cmd/modaudit`: `run(args) int` is the testable entry; `audit` turns `ErrBudget` into `BUNDLE_BUDGET_EXCEEDED` (`NEEDS_HUMAN`).

## Invariants (from the plan)

- Streaming only: never extract a zip to disk, never load a whole archive in memory. Rules touch nothing beyond the zip.
- Deterministic output: stable ordering, no timestamps or absolute paths in reports.
- Rule codes are stable strings; comments derive from codes, never from model text.
- Exit codes: `0` SIGN, `2` REFUSE, `3` NEEDS_HUMAN, `4` REPACKAGE, `1` tool error.
- Normalise entry names (`NormalizeName`: `..\`, non-UTF-8) before traversal checks. Duplicate names with different content are blockers.
- A non-numeric `mod.json` version is a blocker: repackage needs a patch bump and must not guess.

## Tests

Tests write fixture zips to `t.TempDir()` with `writeZip(t, zipEntry{...})` from `internal/audit/fixtures_test.go`; assert with `hasCode` / `findCode` (`rules_archive_test.go`). Use `testLimits()` (`scan_test.go`) for scan-level tests. The golden report test lives in `internal/report` because an `audit` test importing `report` would cycle.
