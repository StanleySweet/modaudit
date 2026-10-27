# Context

Dense project context. Read this before exploring. Keeps token use low.

## What this is

Cross-platform audit + signing tool for 0 A.D. mods on mod.io.

- Manager (hosted, OVH): control plane. Holds mod.io OAuth token, queue, audit
  records, comment drafts, signature records, uploads.
- Go CLI (signer machine): data plane. `queue`, `fetch`, `audit`, `repackage`,
  `sign`, `submit`. Holds revocable manager API key only.
- OpenCode skill: LLM judgement over a compact bundle. Never signs, never posts.

Design: `.docs/design.md`. Decisions: `.docs/decision/`. Plans:
`.docs/plan/01-audit-cli.md` (phase 1); later phases 02 signing, 03 manager,
04 repackage/publish, 05 skill/eval.

## Current state (2026-10-24)

Branch: `feat/audit-cli`. Ledger: `.superpowers/sdd/01-audit-cli/progress.md`.
Done: phase 1 (plan 01) complete: rules, verdict, report, capped bundle,
`modaudit audit` CLI, fuzz tests, README.
Next: phase 02 signing, plan `.docs/plan/02-signing.md` (written, awaiting review).
Build/test: `go build ./...`, `go vet ./...`, `go test ./...`. Golden:
`go test ./internal/report -run TestGoldenRepackage -update`. Fuzz:
`go test ./internal/audit -run '^$' -fuzz FuzzRunOnArbitraryBytes -fuzztime 20s`.
No network/signing/LLM.

## Hard rules

- Never sign bytes different from the bytes distributed.
- Repackage only `REPACKAGE` verdicts (validated but unpackaged). Never fix
  unsafe, broken or compatibility-violating mods.
- Repackage requires human yes, a patch bump in `mod.json` version, re-audit and
  sign of the rebuilt zip.
- Deterministic blockers cannot be cleared by the LLM.
- Comments are drafts; a human approves (`modaudit review`); manager posts.
- Signing requires an interactive terminal. No `--yes`.
- OAuth token never leaves the manager. Signing key never on the server.

## Verdicts

`SIGN` | `REPACKAGE` | `REFUSE` | `NEEDS_HUMAN`

## Facts that shaped it

- mod.io Edit Modfile accepts `metadata_blob`: `SIGN` sets the blob on the
  existing modfile; only `REPACKAGE` uploads a new file (`POST /files`). ADR 0014.
- Signature blob: `{"dependencies":[<mod.json deps>],"minisigs":["<text>", ...]}`.
  One signature per alpha key; engine picks the entry whose key number matches
  its public key, needs `ED`, and fails on any malformed earlier entry
  (`ModIo.cpp` `ParseSignature`). `dependencies` is display only. ADR 0013.
- Per-alpha mod public keys: `modio.public_key` in engine `default.cfg` at each
  release tag (a23 … v0.28.0). Most mods: current alpha only; some cross-alpha.
- Packaging = pyrogenesis `-archivebuild-compress` (xml→xmb, png→dds, dae→pmd).
- Known bug: some mods ship `.xml` without the `.xmb`; absence of compiled
  counterpart is the packaging signal.
- Keys: `~/Library/CloudStorage/OneDrive-Personnel/certificates/sign/keys/*.pem`,
  all password-encrypted. Script: `.../sign/minisign.py`.
- Go minisign: `aead.dev/minisign` (MIT, pure Go, streams, decrypts keys).

## References

- `0ad.wiki/Mod_Verification_Process.md` — audit steps, blob format, compat flag.
- `0ad.wiki/Mod_Publishing_Process.md` — signature guarantee, mod.json mistakes.
- `0ad.wiki/ReleaseProcess.md` — per-alpha key generation.
- `.ref/0ad-community-mod/scripts/modio.py` — real upload path.
- `.ref/0ad-community-mod/.gitea/workflows/jobs.yml` — build → sign → upload.
- `.ref/gh-action-build-pyromod/entrypoint.sh` — archivebuild invocation.
- `../modio-manager/backend/src/plugins/mods.ts` — existing endpoints.
- `../modio-manager/backend/src/services/modioSync.ts` — signature detection.

## Do not

- Run pyrogenesis on content that has not passed the deterministic audit.
- Read or echo the OAuth token.
- Touch clones in `../planned-updates`.
