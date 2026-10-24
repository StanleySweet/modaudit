# modaudit

Deterministic audit of 0 A.D. mod zips before signing. Phase 1 of a
cross-platform audit and signing tool for mods on mod.io.

## Usage

```sh
go build -o modaudit ./cmd/modaudit
modaudit audit --zip mod.zip [--slug S] [--baseline FILE] [--out FILE] [--bundle FILE] [--config FILE]
```

| Flag | Meaning |
|---|---|
| `--zip` | Mod archive to audit (required). |
| `--slug` | mod.io slug; compared case-insensitively with `mod.json` `name`. |
| `--baseline` | Previous `report.json`; its manifest decides which scripts count as changed. |
| `--out` | Report path (default `report.json`). |
| `--bundle` | Write the LLM review bundle (changed scripts only) here. |
| `--config` | Config file (default `$MOD_AUDIT_CONFIG`, then `./config.toml`, then built-in defaults). |

The command prints the verdict, the zip SHA-256 and comment bullets generated
from rule codes.

## Verdicts and exit codes

| Exit | Verdict | Meaning |
|---|---|---|
| 0 | `SIGN` | No blocker, packaged. |
| 2 | `REFUSE` | At least one blocker, or a hard cap aborted the scan. |
| 3 | `NEEDS_HUMAN` | Changed scripts exceed the bundle caps; never sampled silently. |
| 4 | `REPACKAGE` | Valid but unpackaged (e.g. simulation XML without `.xmb`). |
| 1 | — | Tool error. |

## Config

Copy `config.toml.example` to `config.toml`. Phase 1 reads only `[limits]`:
`max_entries`, `max_uncompressed`, `max_ratio`, `max_file_size`,
`max_script_bytes`, `max_bundle_bytes`, `max_bundle_files`. Other keys
(`manager_url`, `target_alpha`, `key_dir`, `pyrogenesis`,
`archivebuild_flags`, `api_key_file`, `api_key_cmd`, `vault_cmd`) are for later
phases. Secrets are referenced by file or command, never inlined.

## What it does not do

No signing, no network, no LLM call. The zip is streamed, never extracted.
`--bundle` only writes a file for a separate LLM skill to read.

## Development

```sh
go vet ./... && go test ./...
go test ./internal/report -run TestGoldenRepackage -update   # regenerate golden report
go test ./internal/audit -run '^$' -fuzz FuzzRunOnArbitraryBytes -fuzztime 20s
```

Design: `.docs/design.md`. Decisions: `.docs/decision/`. Plans: `.docs/plan/`.
