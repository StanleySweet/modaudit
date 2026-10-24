# Mod Audit and Signing Tool — Design

Status: draft for approval
Date: 2026-10-24

## 1. Intent

Give 0 A.D. mod signers a fast, low-token, cross-platform way to audit a mod.io
modfile, refuse it with a queued bullet-point comment, or approve it and sign the
exact bytes that get distributed.

The tool decides nothing irreversible on its own. It audits, recommends and
prepares; a human approves a repackage and approves a signature.

Why now: signing is currently a manual download / inspect / `minisign.py` loop,
the queue lives in a separate hosted manager, and repackaging an unpackaged mod
is manual and error-prone. The same work should be one command plus one
confirmation.

## 2. Goals

- Audit a modfile deterministically, then with an LLM only where it adds signal.
- Refuse with a generic comment built from rule codes; queue it, never post it.
- Repackage *only* mods whose audit passes but whose packaging is wrong.
- Sign the exact distributed bytes, verifiable by the manager.
- Run on macOS, Windows and Linux for audit and signing.
- Keep the mod.io OAuth token on the manager and the signing key off the server.
- Keep per-mod LLM cost near zero for unchanged content.

## 3. Non-goals

- Fixing unsafe, broken or compatibility-violating mods.
- Reviewing compiled binary assets semantically (they are hashed, typed and
  inventoried, not understood).
- A mod.io web UI replacement, or a general mod host.
- Server-side LLM calls.
- Automatically approving comments. Posting always has a human gate.
- Signing mods the signer did not audit.

## 4. Anti-goals

These make the project a failure even if it works:

- Signing bytes different from the bytes distributed.
- A signature the manager cannot verify against the per-alpha trust store.
- A refusal comment posted without human approval.
- Rewriting author content to "fix" a mod.
- The agent being able to complete a signature without the human.

## 5. Constraints

- Modfiles are zips on mod.io; the signature travels in the modfile
  `metadata_blob` as `{"dependencies":[...],"minisigs":[...]}`.
- mod.io's Edit Modfile accepts only `changelog`, `version`, `active`. A new
  signature therefore requires uploading a **new modfile** (`POST /files`),
  which the signer's account can do with game-admin rights.
- `mod.json` carries the *mod* version, not an engine version. The engine/alpha
  binding comes from the minisign key (`minisign-0.28.0.pem` → `0ad=0.28.0`).
- Packaging is normally done by pyrogenesis `-archivebuild-compress`, which
  turns sources (`.xml`, `.png`, `.dae`, …) into compiled assets (`.xmb`,
  `.dds`, `.pmd`, …).
- The current signing keys live in OneDrive as password-encrypted `.pem` files.
- The hosted manager is the only place holding the mod.io token.

## 6. Approaches considered

1. **Python CLI mirroring `minisign.py`.** Shortest to write, matches house
   style. Rejected: per-OS runtime, no static binary, packaging and venv
   friction, higher long-term token cost to maintain across three OSes.
2. **Rust CLI.** Best runtime characteristics. Rejected: higher code and
   dependency cost for no user-visible gain at this size.
3. **Go CLI + hosted manager as control plane (chosen).** Static cross-platform
   binaries, stdlib covers HTTP/JSON/zip/CLI, pure-Go minisign removes the
   external binary, and the manager keeps the token, queue and records.

Within Go, signing uses `aead.dev/minisign` rather than cgo or shelling out to
the C minisign binary: it signs, verifies, decrypts encrypted keys, and streams
the zip, with clean cross-compilation. The official C binary stays in CI as a
cross-check.

## 7. Architecture

```
mod.io  <--OAuth token--  manager (OVH)  <--HTTPS API key--  Go CLI (signer machine)
                             |  queue, records, comment     |
                             |  drafts, signature store     +-- OpenCode skill (LLM judgement)
                             |  uploads (POST /files)
```

- **Manager (control plane)**: queue, artifact download, audit records, comment
  drafts and approval, signature records, mod.io upload, audit log. Holds the
  OAuth token.
- **Go CLI (data plane)**: `queue`, `fetch`, `audit`, `repackage`, `sign`,
  `submit`. Holds a revocable manager API key and never the OAuth token.
- **Skill (judgement)**: reads the compact audit bundle, returns schema-valid
  judgement. No prose goes into public comments.

The CLI never talks to mod.io directly.

`config.toml` (repo root, or `--config`, or `MOD_AUDIT_CONFIG`) holds local
settings: `manager_url`, `target_alpha`, `key_dir`, `pyrogenesis`,
`archivebuild_flags`, `api_key_file`, `api_key_cmd`, `vault_cmd`. Secrets are
referenced, never inlined: the manager API key comes from a `0600` file or a
command, the minisign password from a prompt or a command.

## 8. Verdict model

One verdict per audited artifact:

| Verdict | Meaning | Next |
|---|---|---|
| `SIGN` | Deterministic rules pass; LLM found nothing blocking | Human signs |
| `REPACKAGE` | Rules pass, but packaging is wrong | Human approves repackage → rebuild → re-audit |
| `REFUSE` | Deterministic blocker, or LLM finds real malicious/unsafe code | Queued refusal comment |
| `NEEDS_HUMAN` | Ambiguous, budget exceeded, or conflicting signals | Human reviews evidence |

Rules:

- Deterministic blockers cannot be cleared by the LLM. The LLM can only add
  suspicion.
- The LLM cannot upgrade `REFUSE` to `SIGN` or `REPACKAGE`.
- Any artifact whose bytes changed after audit must be re-audited.

## 9. Deterministic audit

Runs on the zip without extracting to disk; entries are streamed.

**Archive safety**: path traversal, absolute paths, drive-letter paths,
symlinks and hardlink entries, duplicate/case-colliding names, encrypted
entries, nesting depth, entry count, per-entry and total uncompressed size,
compression ratio (zip bomb), non-UTF-8 names, embedded zips/pyromods.

**Layout**: `mod.json` at archive root, single top-level wrapper directory,
`__MACOSX`, `.DS_Store`, `Thumbs.db`, `.git*`, editor backups, `__pycache__`,
nested `.zip`.

**`mod.json`**: parses as JSON; known fields validated (`name`, `version`,
`label`, `description`, `dependencies`, `url`, `ignoreInCompatibilityChecks`);
`name` matches queue slug; version format; dependency types. Unknown fields are
reported, not fatal.

**Compatibility policy**: `ignoreInCompatibilityChecks` present/true is a
blocker — such mods are refused, not silently accepted.

**Script inventory**: every `.js` under `simulation/`, `gui/`, `maps/` and any
`*_triggers.js`; `Engine.*` / `Scripting.*` API usage; `Engine.Crash`,
file read/write, network calls (`XMLHttpRequest`, `fetch`, `WebSocket`),
`eval`/`Function`/`setTimeout(string)`, dynamic script loading; obfuscation
signals (minified long lines, heavy hex/unicode escapes, packers, base64 blobs
that decode to code).

**Assets**: type inventory, extension policy, embedded executables
(`.exe`, `.dll`, `.so`, `.dylib`, `.node`, ELF/Mach-O/PE magic regardless of
extension), external references from `.dae`/`.xml`, oversized assets.

**XML**: well-formedness with an external-entity-disabled parser.

**Diff**: entry-level SHA-256 manifest compared with the last approved version.
Added/changed executable files are the LLM input; unchanged content inherits
approval. Removed files are listed.

**Packaging detection** (pre-repackage, no pyrogenesis run):

- Layout faults from the layout rules, or
- source assets present whose compiled counterpart is absent — notably `.xml`
  without the corresponding `.xmb` (the current known bug ships XML and omits
  XMB), and comparable source/compiled pairs for art.

Only `SIGN`-clean content can become `REPACKAGE`; anything else is `REFUSE`.

## 10. LLM scope and budget

The LLM receives a bundle, not the mod:

- verdict candidate and rule findings,
- `mod.json`,
- added/changed executable files (JavaScript and script-driving XML/JSON),
- the entry inventory diff,
- prior report summary for this mod.

Caps: 60k input tokens or 50 files, whichever comes first. Exceeding a cap
turns the verdict into `NEEDS_HUMAN`; the tool never samples executable code
silently. Binary assets are never sent. The CLI caps by bytes as well (200 KiB
of bundle ≈ 60k tokens), so it never needs a tokenizer.

Invocation contract, so the CLI has no LLM dependency:

1. `audit` writes `bundle.json` and stops.
2. The human (or agent) runs the skill over that bundle; the skill writes
   `judgement.json` matching the schema (verdict, findings with rule code, file
   paths, confidence, no free text reused in comments).
3. `submit` validates `judgement.json` against the schema and rule findings; an
   invalid or inconsistent judgement is rejected, not coerced.

Prompt-injection handling: bundle content is delimited and labelled untrusted;
the model must answer with a fixed JSON schema (verdict, per-finding
confidence, cited file paths, no free text used in public output); any file that
addresses the model or the auditor is itself a finding.

## 11. Repackage flow (only `REPACKAGE`)

1. Resolve packaging faults from the deterministic report.
2. Ask the human: repackage this mod? Show slug, version, faults, artifact
   hash. No answer, no repackage.
3. Bump the patch component of `mod.json` `version` (bugfix bump), nothing
   else. Only dotted numeric versions are eligible (`1.2.3` → `1.2.4`,
   `1.2` → `1.2.1`); anything else (date strings, missing, suffixed) becomes
   `NEEDS_HUMAN` rather than a guessed version.
4. Extract to a scratch directory with traversal protection; drop OS/editor/git
   junk; normalise to a single root.
5. Run pyrogenesis `-archivebuild-compress` with the same engine version as the
   signing key.
6. Build the new zip reproducibly (sorted entries, fixed timestamps).
7. Re-audit the rebuilt zip from scratch.
8. Compare manifests: content changes must be limited to compiled artefacts
   produced by archivebuild plus the `mod.json` version bump. Any other added,
   removed or changed file → abort and queue a refusal/needs-human comment.
9. Human confirms; signature covers the rebuilt zip only.
10. Manager uploads the rebuilt zip as a new modfile with the bumped version and
    an explanatory changelog, attaches the signature in `metadata_blob`, and
    records original hash → rebuilt hash.

Guardrails: never touch unsafe/broken/compat-violating mods; never sign the
original; abort if pyrogenesis is missing, fails, or its version differs from
the key's alpha.

pyrogenesis resolution: `--pyrogenesis <path>` or `PATH`; the CLI probes its
version and requires an exact alpha match with the signing key. Repackaging is
available only where such a build exists; otherwise the verdict stays
`REPACKAGE` with a comment asking the author to package the mod.

## 12. Signing

- Inputs: rebuilt or original zip, the exact SHA-256 audited, target alpha.
- Key: encrypted `.pem` from the vault/OneDrive; alpha selected from the audit
  record, not from filename sorting.
- Alpha source: `config.toml` `target_alpha` (the alpha currently being signed);
  the CLI stamps it onto the audit record. The key's alpha and the queue entry
  must match. `--alpha` is only an assertion, never a way to pick a different
  alpha into a signature.
- Password: prompted on the terminal without echo, or fetched via
  `--password-cmd` (for example `keepassxc-cli show -a Password …`). Never from
  environment variables and never printed.
- Signing: stream the file through `minisign.NewReader`, decrypt the key with
  the password, sign with comments naming the alpha and auditor.
- Local verification: verify the produced signature and the file hash before
  writing the `.minisig`.
- Confirmation: the human must type an exact token (mod slug + new version, or
  the first 12 hex of the SHA-256) shown on the terminal. No `--yes` flag
  exists. Refuse when stdin is not a terminal.
- Linux uses `/dev/tty`, Windows opens `CONIN$`, macOS uses the controlling
  terminal; a single `approval` package wraps this.

## 13. Publish and metadata blob

Manager builds the blob:

```json
{
  "dependencies": ["0ad=0.28.0"],
  "minisigs": ["untrusted comment: …\nRW…\n…"]
}
```

`dependencies` comes from the signing key's alpha, because `mod.json` has no
engine tag. The mod's own `mod.json` dependencies are recorded separately as
metadata and shown to the signer, never substituted into the blob.

Bytes at publish time: the CLI uploads the exact audited artifact to the
manager (`POST /api/audits/{id}/artifact`), which hashes it and refuses if the
hash differs from the audit record. For `SIGN` this is the original modfile; for
`REPACKAGE` it is the rebuilt zip. The manager never trusts a client-supplied
hash and never re-downloads from mod.io to guess.

Upload uses the existing community-mod path: `POST /games/5/mods/{id}/files`
with the zip, `version`, `changelog`, `metadata_blob`, then set the new file
active. Manager verifies the signature against its per-alpha public-key trust
store before publishing, and stores key id, alpha and artifact hashes.

## 14. Comments

Refusal and repackage comments are built from rule codes and fixed bullets, not
LLM prose, so they cost no tokens and stay consistent.

- The CLI creates a **draft** in the manager: verdict, bullets, evidence links.
- Drafts are never posted automatically.
- A signer/admin approves in the manager UI; the manager posts via the mod.io
  token and stores the comment id.
- One open draft per mod/version; posting is idempotent.
- Comments state plainly when a mod was repackaged by WFG and why.

## 15. Manager changes

Changes land in the existing `../modio-manager` Fastify repo (schema, migrations,
endpoints, admin UI), not in this repo. This repo holds the Go CLI, the skill and
the docs.

- `auditor` role and API keys (hashed at rest, revocable, scoped to: read queue,
  download artifact, upload audited artifact, submit audit, create comment
  draft, submit signature).
- Endpoints: `GET /api/version`, queue listing, artifact download, artifact
  upload, audit record create/read, comment draft create/list/approve/post,
  signature submit, repackage/upload record.
- Trust store: an admin imports each alpha's `.pub` (alpha, key id, public key);
  signature verification resolves the key by key id and rejects unknown or
  wrong-alpha keys.
- Comment approval lands in the manager's existing admin area: the approve/post
  endpoint is the primitive, the UI is the normal path, and both write audit-log
  entries with actor and artifact hash.
- Queue population: the existing sync auto-enqueues every unsigned current
  modfile plus any mod whose newest modfile is unsigned or whose approved
  baseline is missing; signed-current mods are skipped; a signer can enqueue
  manually. A new modfile on an already-approved mod re-enqueues and diffs
  against that mod's last approved manifest.
- Signature verification against a per-alpha public-key trust store.
- Audit log entries for every state change, actor and artifact hash.
- Records: original and rebuilt SHA-256/MD5, entry manifests, rule report, LLM
  report, key id, alpha, tool version, pyrogenesis version.
- Retention: manifests and reports kept permanently; original and rebuilt
  artifacts kept 90 days (configurable), except the currently distributed
  artifact.

## 16. Secrets

- mod.io OAuth token: manager `.env`, root-owned, systemd-readable, not in Git.
  SOPS+age only if env files start flowing through Git.
- minisign key: encrypted `.pem`, OneDrive-synced, optional KeePassXC vault;
  never on the OVH host.
- Manager API key: revocable, stored locally with restricted permissions.
- The agent can read neither the OAuth token nor a usable plaintext key.

Threat model: this prevents accidental leakage and casual agent misuse. It does
not survive a compromised signer account with a terminal and the key password.

## 17. Testing and evaluation

- Rule fixtures per rule code, including benign look-alikes.
- Archive abuse: traversal, bombs, symlinks, duplicates, bad encodings.
- Golden report and comment output.
- Fuzz filename and zip header parsing.
- Fake manager and fake mod.io via `httptest`; fake vault; pty approval test.
- Sign → verify with ephemeral keys; refuse on hash mismatch; cross-check
  against official C minisign in CI.
- Manager: role/scoping tests, migrations up/down, comment state machine,
  signature trust store, audit logging.
- Repackage: fixture mod with XML/no XMB; deterministic rebuild hash; abort
  cases (unexpected file changes, wrong engine version).
- Eval corpus of benign and malicious mods: false accept, false refuse, tokens
  per mod; cached-verdict path must make zero LLM calls.
- CI cross-compiles darwin/arm64+amd64, linux/amd64+arm64, windows/amd64.

## 18. Rollout

1. Design + ADRs approved.
2. Repo scaffold, fixtures, rule engine and report (audit only, local files).
3. Signing with pure-Go minisign, pty approval, verification.
4. Manager: auditor key, queue download, audit records, comment drafts.
5. Repackage pipeline behind explicit approval.
6. Manager upload with `metadata_blob` and signature verification.
7. Skill, token budgets, eval corpus.

## 19. Open items

- Exact list of compiled-pair extensions for packaging detection beyond
  XML→XMB (art source/compiled pairs).
- Whether the manager should re-verify the uploaded zip hash after mod.io
  upload (recommended: yes, compare against the upload response).
- Whether refusal drafts may include the author-facing fix hint (currently yes,
  templated).
- Windows signing smoke test on real hardware before claiming Windows support.
