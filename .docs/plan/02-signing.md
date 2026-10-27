# Phase 2 — Signing Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Ship `modaudit sign --report report.json --zip mod.zip [--merge-blob FILE]`: sign exactly the audited bytes with the per-alpha encrypted minisign key, after an interactive exact-token confirmation, verify locally, and write `<zip>.minisig` plus the `metadata_blob` JSON: one signature for `target_alpha` by default, or merged into an existing cross-alpha blob. No network, no manager, no LLM.

**Architecture:** Five new packages behind one command. `internal/trust` is the committed per-alpha public-key table (from engine release tags). `internal/keys` finds `minisign-<alpha>.pem` in `key_dir` and selects by exact alpha. `internal/approval` owns the terminal (`/dev/tty`, `CONIN$`): no-echo password, exact-token confirm, refusal when there is no terminal. `internal/signer` streams the zip once through `minisign.NewReader` and SHA-256 together, refuses on hash mismatch, verifies with the key's own public half. `internal/blob` parses, validates (in engine order) and merges `metadata_blob` JSON. `cmd/modaudit` wires `sign` with preconditions from the phase 1 report and config.

**Tech Stack:** Go 1.26, `aead.dev/minisign` v0.3.0 (pinned, ADR 0003), `golang.org/x/term`, phase 1 packages.

**Spec:** `.docs/design.md` §12, §13 (blob only), §16, §17. Decisions: `.docs/decision/0003`, `0008`, `0012`, `0013` (supersedes `0010`).

## Global Constraints

- Never sign bytes different from the bytes audited: the SHA-256 is computed over the same stream that is signed, then compared with `report.zip_sha256` before anything is written.
- Only reports with verdict `SIGN` are signable. `REPACKAGE` zips are rebuilt and re-audited in phase 04; the rebuilt zip's own `SIGN` report is what gets signed.
- Alpha authority: `config.toml` `target_alpha` picks the key; `--alpha` only asserts and refuses on mismatch. Never select a key by sorting filenames. `minisign-releases.pem` is never a mod key.
- Blob `dependencies` is the report's `mod_json.dependencies`, verbatim (ADR 0013). A `mod.json` engine dependency (`0ad<op><version>`) must admit every alpha the blob serves, using the engine's `CompareVersionStrings` semantics (`source/ps/Mod.cpp`); bare `0ad` admits all.
- Key binding: after decryption the key's public half must equal the `internal/trust` key for `target_alpha`. A key file named for one alpha but holding another refuses.
- Every blob entry written is valid in engine order (`ModIo.cpp` `ParseSignature`): ≥ 4 lines, `untrusted comment: ` / `trusted comment: ` prefixes, 74-byte base64 signature, `ED`, key number in the trust store, verifies against the exact bytes. One bad entry hides the mod from every alpha.
- Merge keeps an existing entry only if it verifies against these bytes with its trust-store key; the same-key entry is replaced; anything else refuses the merge (new bytes never inherit old signatures).
- Password: terminal prompt without echo, or `vault_cmd` / `--password-cmd`. Never from environment variables, never printed, never written to disk, never in an error message.
- Approval: exact token typed on the controlling terminal. No `--yes`. No terminal → refuse. Stdin redirection must not satisfy the prompt.
- Decrypted key lives in memory only; no temp key file, no FIFO, no external `minisign` binary at runtime.
- Signature mode is prehashed (`ED`, BLAKE2b), as produced by C `minisign` ≥ 0.10 and the community-mod workflow.
- Exit codes for `sign`: `0` signed, `1` tool error, `2` precondition refused (verdict, hash, alpha, key), `3` declined at the prompt.
- Builds stay static: `CGO_ENABLED=0` for darwin arm64/amd64, linux arm64/amd64, windows amd64.

## Review Focus

- Zip replaced between audit and sign: hash mismatch must refuse before the password prompt, and again if the file changes during the signing read.
- `echo token | modaudit sign …` must refuse: approval reads the terminal device, not stdin.
- `target_alpha = "0.28.0"` with only `minisign-0.0.27.pem` present must refuse, not fall back to the newest key.
- The password must not appear in errors from `DecryptKey`, `vault_cmd` failures, or panics.
- A `.minisig` produced here must verify with C `minisign -Vm` and the alpha's public key; a C-produced signature must verify here.
- The blob signature text: `\r` removed, trailing newline trimmed, as `minisign.py` and the manager expect.
- Merging into the linux-libertine-style blob (a23b…a27 entries) for 0.28.0 keeps all five old entries when the bytes are unchanged, and refuses when the zip differs.
- `mod.json` `"0ad=0.0.27"` signed for `0.28.0` must refuse: the engine would not load it.

## Phase Roadmap

| Plan | Scope |
|---|---|
| `.docs/plan/01-audit-cli.md` | Deterministic audit, verdict, report, bundle (done) |
| `.docs/plan/02-signing.md` (this) | Key discovery, minisign sign/verify, TTY approval |
| `.docs/plan/03-manager-api.md` | `../modio-manager` schema, scopes, endpoints, UI, trust store |
| `.docs/plan/04-repackage-publish.md` | archivebuild rebuild, upload, `metadata_blob` |
| `.docs/plan/05-skill-eval.md` | Skill contract, eval corpus, token budget tests |

## Facts checked while planning (2026-10-24)

- Real key dir holds `minisign-0.0.23.pem` … `minisign-0.0.27.pem`, `minisign-0.28.0.pem`, `minisign-releases.pem`, `Readme.MD`. Despite the `.pem` suffix these are minisign encrypted secret keys, not PEM.
- `minisign.py` selects by menu over sorted versions and builds the blob with `text.replace("\r", "").rstrip("\n")`; it writes `<name>.minisig`. The community-mod workflow writes `<name>.zip.minisign` with C minisign 0.11.
- Engine `ModIo.cpp` `ParseSignature`: iterate `minisigs`, `continue` on key-number mismatch, `FAIL` (whole mod) on malformed entries met first; requires `ED`. Blob `dependencies` is display only (`gui/modio/modio.js`).
- Mod public keys per release tag (`binaries/data/config/default.cfg` `public_key`): a23 `RWQBhIRg+dOifTWlwgYHe8RfD8bqoDh1cCvygboAl3GOUKiCo0NlF4fw`, a23b `RWTsHxQMrRq4xwHisyBa2rNQfAedcINzbTT83jeX4/ZcfVxqLfWB4y8w`, a24 `RWRcbM/EwV7bucTiQVCcRBhCkYkXmJEO7s4ktyufkB+gW/NxHhOZ38xh`, a25/a25b `RWTVElEmCfAMGk/jtMc2I9/ElBvoJituKdbDWqqj6D69qz2cKexU4gv+`, a26 `RWQa4XiSn+BLxIYXNrXyz68wwTGWyZ7+kxDtZuLHBXkCtt+lLB8VnpdM`, a27/a27.1 `RWQv2alKl8D0zMDJR766jpYvPy4u3y77HL/iKb/lsT1Fnf6ezoMb2x8+`, v0.28.0 `RWRoZZuNzi1wX+Hs5NKAf+GghHwye3mFePfBzOFt3mqYUZAkqAvs69W2`.
- Real cross-alpha blob (linux-libertine) has `dependencies: ["0ad"]` and five entries (a23b…a27 keys, one with a trailing `\n`); C trusted comments are `timestamp:<unix>\tfile:<name>[\thashed]`.
- `aead.dev/minisign` v0.3.0 API: `DecryptKey(password, raw)`, `IsEncrypted`, `NewReader(r)`, `(*Reader).SignWithComments(key, trusted, untrusted) []byte`, `(*Reader).Verify(pub, sig) bool`, `PrivateKey.Public()`, `PrivateKey.ID()`, `Signature.UnmarshalText`.

---

### Task 1: Dependencies

**Files:**
- Modify: `go.mod`, `go.sum`

**Interfaces:**
- Consumes: existing `KeyDir`, `TargetAlpha`, `VaultCmd`; no new config keys.

- [ ] **Step 1:** `go get aead.dev/minisign@v0.3.0 golang.org/x/term@latest && go mod tidy`. Check `go.mod` pins exact versions.
- [ ] **Step 2:** `go test ./...` → PASS. Commit `chore: signing dependencies`.

---

### Task 2: Trust store

**Files:**
- Create: `internal/trust/trust.go`, `internal/trust/trust_test.go`

**Interfaces:**
- Produces: `trust.Key{Alphas []string; Public minisign.PublicKey}`, `trust.ForAlpha(alpha string) (minisign.PublicKey, bool)`, `trust.ByID(id uint64) (trust.Key, bool)`.

Table from "Facts checked" above. Alpha spellings as the engine reports them and as key files are named: `0.0.23` (a23 and a23b keys both listed; key-number lookup disambiguates), `0.0.24` … `0.0.27`, `0.28.0`. Comment each entry with its source tag.

- [ ] **Step 1:** Tests: every key parses; `ForAlpha("0.28.0")` ID equals the ID in `RWRoZZ…`; the six linux-libertine signature key numbers resolve via `ByID`; unknown alpha → false.
- [ ] **Step 2:** Implement. **Step 3:** PASS. Commit `feat: per-alpha public key trust store`.

---

### Task 3: Key discovery

**Files:**
- Create: `internal/keys/keys.go`, `internal/keys/keys_test.go`

**Interfaces:**
- Produces: `keys.Key{Alpha, Path string}`, `keys.Discover(dir string) ([]keys.Key, error)`, `keys.Select(dir, alpha string) (keys.Key, error)`, `keys.ErrNoKey`.

- [ ] **Step 1: Write the failing tests**

```go
func TestSelectExactAlphaOnly(t *testing.T) {
    dir := t.TempDir()
    for _, n := range []string{"minisign-0.0.27.pem", "minisign-releases.pem", "Readme.MD"} {
        os.WriteFile(filepath.Join(dir, n), []byte("x"), 0o600)
    }
    if _, err := keys.Select(dir, "0.28.0"); !errors.Is(err, keys.ErrNoKey) { t.Fatalf("err = %v", err) }
    k, err := keys.Select(dir, "0.0.27")
    if err != nil || k.Alpha != "0.0.27" { t.Fatalf("%+v %v", k, err) }
    if _, err := keys.Select(dir, "releases"); !errors.Is(err, keys.ErrNoKey) { t.Fatal("release key selectable") }
}
```

Also: `Discover` returns keys sorted by name for display only; an alpha must match `^\d+(\.\d+)+$`; empty `dir` is an error naming `key_dir`; `Select("")` is an error naming `target_alpha`.

- [ ] **Step 2:** Run, confirm failure. **Step 3:** Implement. **Step 4:** PASS. Commit `feat: per-alpha key discovery`.

---

### Task 4: Terminal approval

**Files:**
- Create: `internal/approval/approval.go`, `internal/approval/tty_unix.go`, `internal/approval/tty_windows.go`, `internal/approval/approval_test.go`

**Interfaces:**
- Produces: `approval.Terminal` interface `{ ReadPassword(prompt string) ([]byte, error); ReadLine(prompt string) (string, error); Println(string); Close() error }`.
- Produces: `approval.Open() (Terminal, error)` — Unix opens `/dev/tty`, Windows opens `CONIN$`/`CONOUT$`; `approval.ErrNoTerminal` when the device cannot be opened or `term.IsTerminal` is false.
- Produces: `approval.Confirm(t Terminal, summary []string, token string) (bool, error)` — prints the summary and token, reads one line, returns true only for an exact match after trimming the line ending.

- [ ] **Step 1:** Tests use a fake `Terminal`: exact token → true; token with extra spaces inside, wrong case, prefix, or empty → false; read error → error. `Confirm` never accepts an empty token argument (programming error → error).
- [ ] **Step 2:** Implement `Open` per OS with build tags; `ReadPassword` uses `term.ReadPassword` on the device fd. No method reads `os.Stdin`.
- [ ] **Step 3:** Manual check documented in the task log: `echo x | go run ./cmd/modaudit sign …` still prompts on the terminal; `go run … </dev/null` with `setsid` (no controlling tty) refuses with `ErrNoTerminal`.
- [ ] **Step 4:** `GOOS=windows go build ./...` succeeds. Commit `feat: terminal approval`.

---

### Task 5: Password source

**Files:**
- Create: `internal/approval/password.go`, `internal/approval/password_test.go`

**Interfaces:**
- Produces: `approval.Password(t Terminal, cmd string, keyName string) ([]byte, error)`.

Empty `cmd` → `t.ReadPassword("Password for <keyName>: ")`. Otherwise split `cmd` with a quote-aware splitter (single and double quotes, no shell, no expansion), run it with stdin and stderr attached to the terminal device (so `keepassxc-cli` can ask for its own database password), capture stdout, strip one trailing `\n` or `\r\n`. Non-zero exit → error `password command failed: exit N` with no stdout content. Empty output → error.

- [ ] **Step 1:** Tests: splitter cases (`a "b c" 'd e'` → 3 args; unbalanced quote → error); a helper-process test (`os.Args[0] -test.run=TestHelper`) printing `secret\n` → `secret`; failing command error message does not contain its stdout.
- [ ] **Step 2:** Implement. **Step 3:** PASS. Commit `feat: password prompt and vault command`.

---

### Task 6: Signer

**Files:**
- Create: `internal/signer/signer.go`, `internal/signer/signer_test.go`

**Interfaces:**
- Produces: `signer.Request{ZipPath, WantSHA256, Alpha string; Key minisign.PrivateKey}`.
- Produces: `signer.Result{Signature []byte; SHA256 string; KeyID uint64}`.
- Produces: `signer.Sign(req Request) (Result, error)`, `signer.ErrHashMismatch`, `signer.ErrWrongKey`.

`Sign`: open the zip, `io.TeeReader` into SHA-256, wrap with `minisign.NewReader`, `io.Copy(io.Discard, r)`; compare the hex digest with `WantSHA256` (case-insensitive) → `ErrHashMismatch` before returning any signature. Before reading, require `key.Public()` to equal `trust.ForAlpha(Alpha)` → else `ErrWrongKey`. Trusted comment matches C minisign so all blob entries look alike: `timestamp:<unix>\tfile:<base name>\thashed`. Untrusted comment: `signature from minisign secret key`. The auditor is recorded by the manager (phase 03), not in the signature. Then re-open the file and verify with `minisign.NewReader(...).Verify(key.Public().(minisign.PublicKey), sig)`; failure is an error (catches a file changed after the first read).

- [ ] **Step 1: Write the failing tests** with an ephemeral key from `minisign.GenerateKey(rand.Reader)`:

```go
func TestSignVerifiesAndRefusesMismatch(t *testing.T) {
    pub, priv, _ := minisign.GenerateKey(rand.Reader)
    p := filepath.Join(t.TempDir(), "m.zip"); os.WriteFile(p, []byte("zip bytes"), 0o600)
    sum := sha256.Sum256([]byte("zip bytes"))
    res, err := signer.Sign(signer.Request{ZipPath: p, WantSHA256: hex.EncodeToString(sum[:]), Alpha: "0.28.0", Key: priv})
    if err != nil { t.Fatal(err) }
    if !minisign.Verify(pub, []byte("zip bytes"), res.Signature) { t.Fatal("does not verify") }
    if _, err := signer.Sign(signer.Request{ZipPath: p, WantSHA256: strings.Repeat("0", 64), Alpha: "0.28.0", Key: priv}); !errors.Is(err, signer.ErrHashMismatch) {
        t.Fatalf("err = %v", err)
    }
}
```

Also: signature text second line starts with `RU` (prehashed `ED`); trusted comment ends with `\thashed`; a key whose public half is not the trust-store key for `Alpha` → `ErrWrongKey` (tests swap in a test trust table via an unexported hook).

- [ ] **Step 2:** Run, confirm failure. **Step 3:** Implement. **Step 4:** PASS. Commit `feat: stream signing with hash and key checks`.

---

### Task 7: Blob parse, validate, merge

**Files:**
- Create: `internal/blob/blob.go`, `internal/blob/blob_test.go`, `internal/blob/testdata/linux-libertine.json`

**Interfaces:**
- Produces: `blob.Blob{Dependencies []string; Minisigs []string}` (JSON `dependencies`, `minisigs`).
- Produces: `blob.Parse([]byte) (Blob, error)`, `blob.Validate(b Blob, zipPath string) ([]blob.Entry, error)` with `blob.Entry{KeyID uint64; Alphas []string}`, `blob.Merge(old Blob, deps []string, sig []byte, zipPath string) (Blob, error)`, `blob.Marshal(Blob) ([]byte, error)`.

`Validate` mirrors `ParseSignature` per entry (≥ 4 `\n`-split lines, prefixes, 74-byte base64 line 2, `ED`), then requires a trust-store key and a successful `minisign` verification against the zip bytes; duplicate key numbers are an error. `Merge` normalises the new signature (drop `\r`, trim trailing `\n`), replaces the same-key entry or appends, keeps other entries only when `Validate` passes for them, and sets `Dependencies = deps`. Without `--merge-blob` the CLI calls `Merge(Blob{}, deps, sig, zip)`. `Marshal` uses two-space indent.

- [ ] **Step 1:** Tests: the linux-libertine fixture parses and every entry resolves to a trust-store key (structure only: the zip is not available, so `Validate` is exercised with ephemeral keys through the test trust hook); merge replaces same-key entry, appends a new one, refuses when an old entry does not verify against the bytes, refuses a malformed entry; output has no `\r`.
- [ ] **Step 2:** Implement. **Step 3:** PASS. Commit `feat: metadata blob validate and merge`.

---

### Task 9: Engine dependency rule

**Files:**
- Create: `internal/audit/enginever.go`, `internal/audit/enginever_test.go`
- Modify: `internal/audit/scan.go`, `internal/audit/rules_modjson.go`, `internal/report/report.go`, `cmd/modaudit/main.go`

**Interfaces:**
- Produces: `audit.EngineAdmits(deps []string, alpha string) bool`; `audit.Options.TargetAlpha string`; rule code `MODJSON_ENGINE_MISMATCH` (blocker) with comment text.

Port `Mod::CompareVersionStrings` exactly (split on `-,_`, keep the first part, split on `.`, integer compare over the shorter length, then length rule). Operators checked in engine order `<=`, `>=`, `=`, `<`, `>`; first found wins. Only entries whose name before the operator is `0ad` are checked; bare `0ad` admits. `audit` passes `config.target_alpha`; empty alpha skips the rule. `sign` re-checks every alpha in the merged blob.

- [ ] **Step 1:** Table tests from the engine: `0.0.25 <= 0.0.24` false, `0.28.0 >= 0.0.27` true, `0.28.0 = 0.28` false, `0.0.27 = 0.0.27` true, bare `0ad` true.
- [ ] **Step 2:** Implement and wire. Regenerate the golden report only if it changes. **Step 3:** PASS. Commit `feat: engine dependency compatibility rule`.

---

### Task 10: C minisign cross-check

**Files:**
- Create: `internal/signer/compat_test.go`

Skips unless `minisign` is on `PATH` (CI installs 0.11 like the community-mod workflow).

- [ ] **Step 1:** Go → C: generate an ephemeral key, write the public key with `MarshalText`, sign a temp file with `signer.Sign`, run `minisign -Vm <file> -p <pub>` → exit 0.
- [ ] **Step 2:** C → Go: `minisign -G -W -p pub -s sec` (unencrypted, temp dir), `minisign -S -s sec -m file`, parse `sec` via `minisign.PrivateKey.UnmarshalText` is not needed; verify the `.minisig` with `minisign.PublicKeyFromFile` + `Reader.Verify`.
- [ ] **Step 3:** Encrypted-key path: `minisign -G -p pub -s sec` fed a password through a pty is out of scope for CI; instead Task 12 adds a manual real-key smoke test.
- [ ] **Step 4:** Commit `test: cross-check signatures with C minisign`.

---

### Task 11: `modaudit sign` command

**Files:**
- Modify: `cmd/modaudit/main.go`, `cmd/modaudit/main_test.go`
- Create: `cmd/modaudit/sign.go`

**Interfaces:**
- Produces: `modaudit sign --report FILE --zip FILE [--alpha A] [--merge-blob FILE] [--password-cmd CMD] [--out-dir DIR] [--config FILE]`.
- Internal seam: `signDeps{openTerminal func() (approval.Terminal, error)}` so tests inject a fake terminal; `main` uses `approval.Open`.

Order is fixed, and nothing touching the key happens before step 5:

1. Load config (same resolution as `audit`). Require `key_dir`, `target_alpha`; `target_alpha` must be in `internal/trust`.
2. Read the report; require `schema_version == 1` and `verdict == "SIGN"` → else exit 2.
3. Hash the zip; require equality with `report.zip_sha256` → else exit 2. (Cheap early refusal; `signer.Sign` re-checks on the signed stream.)
4. `--alpha`, if given, must equal `target_alpha` → else exit 2. `keys.Select(key_dir, target_alpha)` → `ErrNoKey` exits 2. `--merge-blob`, if given: `blob.Validate` against the zip now (before any prompt) → failure exits 2. `audit.EngineAdmits(mod_json.dependencies, a)` for `target_alpha` and every alpha already in the blob → else exit 2.
5. `approval.Open()` → `ErrNoTerminal` exits 2. Print summary: slug, `mod.json` name/version/dependencies, zip path, SHA-256, alpha, key file, alphas already in the merge blob. Token: first 12 hex of the SHA-256. `Confirm` false → exit 3.
6. Password (`--password-cmd`, else `vault_cmd`, else prompt). Read the key file, `minisign.DecryptKey`; on error print `cannot decrypt <key file>` (no password, no library message) and exit 1. Zero the password slice after use.
7. `signer.Sign` (`ErrWrongKey` exits 2); `blob.Merge`; write `<out-dir>/<zip base>.minisig` (0644) and `<out-dir>/<zip base>.blob.json` (0644). Default `--out-dir` is the zip's directory. Refuse to overwrite an existing `.minisig` (exit 1).
8. Print key ID (hex), signature path, blob path. Exit 0.

- [ ] **Step 1:** Tests with a fake terminal and an ephemeral encrypted key written via `minisign.EncryptKey` into a temp `key_dir` as `minisign-0.28.0.pem`:
  - happy path → exit 0, `.minisig` verifies, blob `dependencies` equals `mod.json`'s, one entry;
  - merge into a blob holding a valid other-alpha entry over the same bytes → two entries; same blob over different bytes → 2;
  - key file for `0.28.0` holding a non-trust-store key → 2;
  - `verdict: REPACKAGE` → 2; zip modified after audit → 2; `--alpha 0.0.27` → 2; key dir with only `minisign-0.0.27.pem` → 2;
  - wrong token → 3 and no files written; wrong password → 1, error output does not contain the password;
  - `openTerminal` returning `ErrNoTerminal` → 2; existing `.minisig` → 1.
- [ ] **Step 2:** Implement. **Step 3:** `go vet ./... && go test ./...` → PASS. Commit `feat: sign command with approval and preconditions`.

---

### Task 12: Cross-compile, real-key smoke test, docs

**Files:**
- Modify: `README.md`, `.docs/context.md`, `.superpowers/sdd/02-signing/progress.md`

- [ ] **Step 1:** `for t in darwin/arm64 darwin/amd64 linux/arm64 linux/amd64 windows/amd64; do CGO_ENABLED=0 GOOS=${t%/*} GOARCH=${t#*/} go build -o /dev/null ./cmd/modaudit; done` → all succeed.
- [ ] **Step 2 (human, real key):** audit a disposable signable zip, then `modaudit sign` with `key_dir` pointing at the real key directory and `target_alpha = "0.28.0"`. Verify with C minisign and the alpha's public key: `minisign -Vm <zip> -p <alpha pub>`. Record result in the ledger. The agent does not run this step and never handles the password.
- [ ] **Step 3:** README: `sign` usage, exit codes, precondition list, password sources, outputs. Context: phase 2 done, next plan 03.
- [ ] **Step 4:** Commit `docs: signing usage`.

---

## Self-Review

- **Spec coverage:** §12 inputs/key/alpha/password/streaming/local verify/confirmation/per-OS terminal → Tasks 2–6, 11; §13 blob shape and per-alpha merge (ADR 0013) → Tasks 2, 7, 9 (publishing stays in phase 04); §16 secrets → Global Constraints + Task 4/7 tests; §17 sign→verify, mismatch refusal, C cross-check, pty approval → Tasks 4, 6, 10, 11.
- **Deferred:** manager upload of the artifact and signature records (phase 03/04), queue-record alpha cross-check (phase 03, needs the manager), Windows real-hardware approval smoke test (ADR 0012; tracked in design §19).
- **Choices made here, flag in review:** C-style trusted comment (auditor recorded by manager instead); `<zip>.minisig` + `<zip>.blob.json` filenames; exit codes `2`/`3` for sign; quote-aware splitter instead of a shell for `vault_cmd`; `0.0.23` maps to both a23 and a23b keys.
- **Revised 2026-10-24** after a real cross-alpha blob and engine source showed one signature per alpha and `mod.json` dependencies (ADR 0013).
