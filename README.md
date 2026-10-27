# modaudit

Audit, repackage and sign 0 A.D. mods published on mod.io. The CLI runs on the
signer's machine; the [mod-io-manager](https://github.com/StanleySweet/mod-io-manager)
server holds the queue, the mod.io token and the audit history. Nothing is written
to mod.io without a human answer on the terminal.

## How it works

```
mod.io ──sync every 30 min──> manager: queue one audit per unsigned current version
                                   │
signer's Mac:  modaudit process-queue   (unattended: download, audit, submit report)
                                   │
signer's Mac:  modaudit review          (one decision per mod)
                                   │
manager ──after verifying hash and signature──> mod.io (signature, new file, comment)
```

## Setup (once)

1. `go build -o ~/.local/bin/modaudit ./cmd/modaudit`
2. `cp config.toml.example config.toml` and set:
   - `manager_url`: `https://mod-io-manager-api.wildfiregames.ovh`
   - `api_key_file`: a `0600` file holding a manager API key. Create the key on the
     manager's **API Keys** admin page (it is shown once; only its hash is stored).
   - `target_alpha`: the release being signed, e.g. `0.28.0`.
   - `key_dir`: folder with the encrypted `minisign-<alpha>.pem` keys.
   - `pyrogenesis`: the engine binary of exactly `target_alpha`, e.g.
     `/Applications/0 A.D..app/Contents/MacOS/pyrogenesis` (used for repackaging).
   - `vault_cmd` (optional): a command printing the key password, e.g.
     `security find-generic-password -a <user> -s modaudit-minisign-0.28.0 -w`.
     It runs without a shell. Empty means a password prompt once per review session.
3. Optional: run the worker in the background with a launchd agent running
   `modaudit process-queue --config <path>/config.toml --interval 60`.

## Routine

**Audit**, unattended:

```sh
modaudit process-queue --config config.toml          # Ctrl-C when idle; --once for one task
```

One line per mod: name, size, verdict, submitted. Approval is never needed here.

**Review**, when you have a few minutes:

```sh
modaudit review --config config.toml
```

For each audited mod it shows the verdict, findings and comment draft:

| Verdict | Key | Effect |
|---|---|---|
| `SIGN` | `s`, then type the 12-hex token | Downloads and re-checks the zip, signs it; the manager re-hashes the modfile from mod.io, verifies the signature and sets `metadata_blob` on the existing file. |
| `REPACKAGE` | `r`, then the token | Strips wrapper/junk, patch-bumps `mod.json`, runs `pyrogenesis -archivebuild-compress`, allows only compiled `*.cached.*` additions, re-audits to `SIGN`, signs; the manager uploads it as a new active modfile and posts a comment saying WFG repackaged it. |
| `REFUSE` | `c` | Posts the rule-based comment on the mod. |
| `NEEDS_HUMAN` | look yourself, then `d` | Closes the task. |
| any | `d` / Enter | Dismiss (no mod.io write) / skip until next review. |

`OUTDATED` and `UNRELEASED` mods (their `mod.json` excludes `target_alpha`) are
never shown and never commented on. A newer modfile is queued normally.

The token is the first 12 hex characters of the SHA-256 of the exact bytes being
signed; typing it is the approval. A failed mod.io write comes back in the next
review with its error.

**Check** results on the manager's **Audits** page: verdict, findings by
severity, comment draft, review status.

**New release**: set `target_alpha`, `pyrogenesis` and the key, then re-queue the
`OUTDATED`/`UNRELEASED` tasks on the manager.

## Commands

```sh
modaudit audit --zip mod.zip [--slug S] [--baseline FILE] [--out FILE] [--bundle FILE] [--config FILE]
modaudit sign --report report.json --zip mod.zip [--merge-blob FILE] [--out-dir DIR]
modaudit process-queue [--once] [--interval SECONDS] [--verbose] [--config FILE]
modaudit review [--config FILE]
```

`audit` works offline on a local zip and prints the verdict, SHA-256 and comment
bullets. Config defaults to `$MOD_AUDIT_CONFIG`, then `./config.toml`.

## Verdicts and exit codes

| Exit | Verdict | Meaning |
|---|---|---|
| 0 | `SIGN` | No blocker, packaged. |
| 2 | `REFUSE` | At least one blocker, or a hard cap stopped the scan (the cap is reported). |
| 3 | `NEEDS_HUMAN` | Changed scripts exceed the bundle caps; never sampled silently. |
| 4 | `REPACKAGE` | Valid but unpackaged (e.g. simulation XML without a compiled `.xmb`). |
| 5 | `OUTDATED` | `mod.json` caps the engine below `target_alpha`. |
| 6 | `UNRELEASED` | `mod.json` needs an engine newer than `target_alpha`. |
| 1 | — | Tool error. |

## Security

- The mod.io OAuth token stays on the manager; the CLI only holds a revocable API key.
- Signing keys stay on the signer's machine; the password is held in memory for one
  review session.
- The manager never trusts the client: it re-hashes the bytes and verifies every
  minisig against the per-alpha public keys before writing to mod.io.

## Development

```sh
go vet ./... && go test ./...
go test ./internal/report -run TestGoldenRepackage -update   # regenerate golden report
go test ./internal/audit -run '^$' -fuzz FuzzRunOnArbitraryBytes -fuzztime 20s
```

Design: `.docs/design.md`. Decisions: `.docs/decision/`. Plans: `.docs/plan/`.
Manager deploy notes live in the mod-io-manager repo.
