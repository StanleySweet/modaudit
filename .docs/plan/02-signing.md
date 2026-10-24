# Phase 2 — Signing Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Ship `modaudit sign --report report.json --zip mod.zip`: sign exactly the audited bytes with the per-alpha encrypted minisign key, after an interactive exact-token confirmation, verify locally, and write `<zip>.minisig` plus the `metadata_blob` JSON. No network, no manager, no LLM.

**Architecture:** Four new packages behind one command. `internal/keys` finds `minisign-<alpha>.pem` in `key_dir` and selects by exact alpha. `internal/approval` owns the terminal (`/dev/tty`, `CONIN$`): no-echo password, exact-token confirm, refusal when there is no terminal. `internal/signer` streams the zip once through `minisign.NewReader` and SHA-256 together, refuses on hash mismatch, verifies with the key's own public half, and builds the blob. `cmd/modaudit` wires `sign` with preconditions from the phase 1 report and config.

**Tech Stack:** Go 1.26, `aead.dev/minisign` v0.3.0 (pinned, ADR 0003), `golang.org/x/term`, phase 1 packages.

**Spec:** `.docs/design.md` §12, §13 (blob only), §16, §17. Decisions: `.docs/decision/0003`, `0008`, `0010`, `0012`.

## Global Constraints

- Never sign bytes different from the bytes audited: the SHA-256 is computed over the same stream that is signed, then compared with `report.zip_sha256` before anything is written.
- Only reports with verdict `SIGN` are signable. `REPACKAGE` zips are rebuilt and re-audited in phase 04; the rebuilt zip's own `SIGN` report is what gets signed.
- Alpha authority: `config.toml` `target_alpha` picks the key; `--alpha` only asserts and refuses on mismatch. Never select a key by sorting filenames. `minisign-releases.pem` is never a mod key.
- Blob `dependencies` is `["0ad=<alpha>"]` from the key, never from `mod.json` (ADR 0010).
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
- `aead.dev/minisign` v0.3.0 API: `DecryptKey(password, raw)`, `IsEncrypted`, `NewReader(r)`, `(*Reader).SignWithComments(key, trusted, untrusted) []byte`, `(*Reader).Verify(pub, sig) bool`, `PrivateKey.Public()`, `PrivateKey.ID()`, `Signature.UnmarshalText`.

---

### Task 1: Dependencies and config

**Files:**
- Modify: `go.mod`, `go.sum`, `config.toml.example`
- Modify: `internal/config/config.go`, `internal/config/config_test.go`

**Interfaces:**
- Produces: `config.Config.Auditor string` (`toml:"auditor"`). Existing `KeyDir`, `TargetAlpha`, `VaultCmd` are consumed as is.

- [ ] **Step 1:** Test that `auditor = "stan"` loads and that a missing `auditor` leaves it empty.
- [ ] **Step 2:** Add the field and the example key (`auditor = ""  # name in the trusted comment`).
- [ ] **Step 3:** `go get aead.dev/minisign@v0.3.0 golang.org/x/term@latest && go mod tidy`. Check `go.mod` pins exact versions.
- [ ] **Step 4:** `go test ./...` → PASS. Commit `feat: signing dependencies and auditor config`.

---

### Task 2: Key discovery

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

### Task 3: Terminal approval

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

### Task 4: Password source

**Files:**
- Create: `internal/approval/password.go`, `internal/approval/password_test.go`

**Interfaces:**
- Produces: `approval.Password(t Terminal, cmd string, keyName string) ([]byte, error)`.

Empty `cmd` → `t.ReadPassword("Password for <keyName>: ")`. Otherwise split `cmd` with a quote-aware splitter (single and double quotes, no shell, no expansion), run it with stdin and stderr attached to the terminal device (so `keepassxc-cli` can ask for its own database password), capture stdout, strip one trailing `\n` or `\r\n`. Non-zero exit → error `password command failed: exit N` with no stdout content. Empty output → error.

- [ ] **Step 1:** Tests: splitter cases (`a "b c" 'd e'` → 3 args; unbalanced quote → error); a helper-process test (`os.Args[0] -test.run=TestHelper`) printing `secret\n` → `secret`; failing command error message does not contain its stdout.
- [ ] **Step 2:** Implement. **Step 3:** PASS. Commit `feat: password prompt and vault command`.

---

### Task 5: Signer and blob

**Files:**
- Create: `internal/signer/signer.go`, `internal/signer/signer_test.go`

**Interfaces:**
- Produces: `signer.Request{ZipPath, WantSHA256, Alpha, Auditor string; Key minisign.PrivateKey}`.
- Produces: `signer.Result{Signature []byte; SHA256 string; KeyID uint64}`.
- Produces: `signer.Sign(req Request) (Result, error)`, `signer.ErrHashMismatch`, `signer.Blob(alpha string, sig []byte) ([]byte, error)`.

`Sign`: open the zip, `io.TeeReader` into SHA-256, wrap with `minisign.NewReader`, `io.Copy(io.Discard, r)`; compare the hex digest with `WantSHA256` (case-insensitive) → `ErrHashMismatch` before returning any signature. Trusted comment: `file:<base name> sha256:<hex> 0ad=<alpha> auditor:<auditor>`. Untrusted comment: `signature from modaudit secret key`. Then re-open the file and verify with `minisign.NewReader(...).Verify(key.Public().(minisign.PublicKey), sig)`; failure is an error (catches a file changed after the first read). `Blob` returns `{"dependencies":["0ad=<alpha>"],"minisigs":["<sig without \r, trailing \n trimmed>"]}` with two-space indent.

- [ ] **Step 1: Write the failing tests** with an ephemeral key from `minisign.GenerateKey(rand.Reader)`:

```go
func TestSignVerifiesAndRefusesMismatch(t *testing.T) {
    pub, priv, _ := minisign.GenerateKey(rand.Reader)
    p := filepath.Join(t.TempDir(), "m.zip"); os.WriteFile(p, []byte("zip bytes"), 0o600)
    sum := sha256.Sum256([]byte("zip bytes"))
    res, err := signer.Sign(signer.Request{ZipPath: p, WantSHA256: hex.EncodeToString(sum[:]), Alpha: "0.28.0", Auditor: "t", Key: priv})
    if err != nil { t.Fatal(err) }
    if !minisign.Verify(pub, []byte("zip bytes"), res.Signature) { t.Fatal("does not verify") }
    if _, err := signer.Sign(signer.Request{ZipPath: p, WantSHA256: strings.Repeat("0", 64), Alpha: "0.28.0", Key: priv}); !errors.Is(err, signer.ErrHashMismatch) {
        t.Fatalf("err = %v", err)
    }
}
```

Also: signature text second line starts with `RU` (prehashed `ED`); trusted comment contains `0ad=0.28.0`; `Blob` output decodes to the exact struct and contains no `\r`.

- [ ] **Step 2:** Run, confirm failure. **Step 3:** Implement. **Step 4:** PASS. Commit `feat: stream signing with hash check and blob`.

---

### Task 6: C minisign cross-check

**Files:**
- Create: `internal/signer/compat_test.go`

Skips unless `minisign` is on `PATH` (CI installs 0.11 like the community-mod workflow).

- [ ] **Step 1:** Go → C: generate an ephemeral key, write the public key with `MarshalText`, sign a temp file with `signer.Sign`, run `minisign -Vm <file> -p <pub>` → exit 0.
- [ ] **Step 2:** C → Go: `minisign -G -W -p pub -s sec` (unencrypted, temp dir), `minisign -S -s sec -m file`, parse `sec` via `minisign.PrivateKey.UnmarshalText` is not needed; verify the `.minisig` with `minisign.PublicKeyFromFile` + `Reader.Verify`.
- [ ] **Step 3:** Encrypted-key path: `minisign -G -p pub -s sec` fed a password through a pty is out of scope for CI; instead Task 8 adds a manual real-key smoke test.
- [ ] **Step 4:** Commit `test: cross-check signatures with C minisign`.

---

### Task 7: `modaudit sign` command

**Files:**
- Modify: `cmd/modaudit/main.go`, `cmd/modaudit/main_test.go`
- Create: `cmd/modaudit/sign.go`

**Interfaces:**
- Produces: `modaudit sign --report FILE --zip FILE [--alpha A] [--password-cmd CMD] [--out-dir DIR] [--config FILE]`.
- Internal seam: `signDeps{openTerminal func() (approval.Terminal, error)}` so tests inject a fake terminal; `main` uses `approval.Open`.

Order is fixed, and nothing touching the key happens before step 5:

1. Load config (same resolution as `audit`). Require `key_dir`, `target_alpha`, `auditor`.
2. Read the report; require `schema_version == 1` and `verdict == "SIGN"` → else exit 2.
3. Hash the zip; require equality with `report.zip_sha256` → else exit 2. (Cheap early refusal; `signer.Sign` re-checks on the signed stream.)
4. `--alpha`, if given, must equal `target_alpha` → else exit 2. `keys.Select(key_dir, target_alpha)` → `ErrNoKey` exits 2.
5. `approval.Open()` → `ErrNoTerminal` exits 2. Print summary: slug, `mod.json` name/version, zip path, SHA-256, alpha, key file, auditor. Token: first 12 hex of the SHA-256. `Confirm` false → exit 3.
6. Password (`--password-cmd`, else `vault_cmd`, else prompt). Read the key file, `minisign.DecryptKey`; on error print `cannot decrypt <key file>` (no password, no library message) and exit 1. Zero the password slice after use.
7. `signer.Sign`; write `<out-dir>/<zip base>.minisig` (0644) and `<out-dir>/<zip base>.blob.json` (0644). Default `--out-dir` is the zip's directory. Refuse to overwrite an existing `.minisig` (exit 1).
8. Print key ID (hex), signature path, blob path. Exit 0.

- [ ] **Step 1:** Tests with a fake terminal and an ephemeral encrypted key written via `minisign.EncryptKey` into a temp `key_dir` as `minisign-0.28.0.pem`:
  - happy path → exit 0, `.minisig` verifies, blob has `0ad=0.28.0`;
  - `verdict: REPACKAGE` → 2; zip modified after audit → 2; `--alpha 0.0.27` → 2; key dir with only `minisign-0.0.27.pem` → 2;
  - wrong token → 3 and no files written; wrong password → 1, error output does not contain the password;
  - `openTerminal` returning `ErrNoTerminal` → 2; existing `.minisig` → 1.
- [ ] **Step 2:** Implement. **Step 3:** `go vet ./... && go test ./...` → PASS. Commit `feat: sign command with approval and preconditions`.

---

### Task 8: Cross-compile, real-key smoke test, docs

**Files:**
- Modify: `README.md`, `.docs/context.md`, `.superpowers/sdd/02-signing/progress.md`

- [ ] **Step 1:** `for t in darwin/arm64 darwin/amd64 linux/arm64 linux/amd64 windows/amd64; do CGO_ENABLED=0 GOOS=${t%/*} GOARCH=${t#*/} go build -o /dev/null ./cmd/modaudit; done` → all succeed.
- [ ] **Step 2 (human, real key):** audit a disposable signable zip, then `modaudit sign` with `key_dir` pointing at the real key directory and `target_alpha = "0.28.0"`. Verify with C minisign and the alpha's public key: `minisign -Vm <zip> -p <alpha pub>`. Record result in the ledger. The agent does not run this step and never handles the password.
- [ ] **Step 3:** README: `sign` usage, exit codes, precondition list, password sources, outputs. Context: phase 2 done, next plan 03.
- [ ] **Step 4:** Commit `docs: signing usage`.

---

## Self-Review

- **Spec coverage:** §12 inputs/key/alpha/password/streaming/local verify/confirmation/per-OS terminal → Tasks 2–7; §13 blob shape → Task 5 (publishing stays in phase 04); §16 secrets → Global Constraints + Task 4/7 tests; §17 sign→verify, mismatch refusal, C cross-check, pty approval → Tasks 3, 5, 6, 7.
- **Deferred:** manager upload of the artifact and signature records (phase 03/04), queue-record alpha cross-check (phase 03, needs the manager), Windows real-hardware approval smoke test (ADR 0012; tracked in design §19).
- **Choices made here, flag in review:** trusted-comment format; `<zip>.minisig` + `<zip>.blob.json` filenames; exit codes `2`/`3` for sign; `auditor` config key; quote-aware splitter instead of a shell for `vault_cmd`.
