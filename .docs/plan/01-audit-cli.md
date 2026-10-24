# Phase 1 — Audit CLI Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Ship `modaudit audit <zip>`: deterministic zip audit, verdict, JSON report, comment bullets and an LLM bundle, with no network, no signing and no LLM call inside the binary.

**Architecture:** One Go module. `internal/audit` streams a zip once into an inventory and runs a fixed rule list over it; `internal/report` serialises the result; `internal/bundle` re-reads only changed script files under a byte cap; `cmd/modaudit` wires flags, config and exit codes. Rules never touch the network or the filesystem beyond the zip.

**Tech Stack:** Go 1.26, standard library (`archive/zip`, `crypto/sha256`, `encoding/json`, `encoding/xml`, `flag`, `regexp`), `github.com/BurntSushi/toml` for `config.toml`.

**Spec:** `.docs/design.md` (sections 8, 9, 10, 14, 17). Decisions: `.docs/decision/0002`, `0004`, `0005`, `0010`.

## Global Constraints

- Go only; the sole non-stdlib dependency is `github.com/BurntSushi/toml`.
- No network calls, no signing, no LLM calls in this phase.
- Streaming only: never extract a zip to disk, never load a whole archive into memory.
- Hard caps: 10 000 entries, 2 GiB uncompressed total, 100:1 ratio, 64 MiB per entry, 2 MiB per script file read, 200 KiB / 50 files per bundle.
- Deterministic output: stable ordering, no timestamps or absolute paths in reports.
- Exit codes: `0` SIGN, `2` REFUSE, `3` NEEDS_HUMAN, `4` REPACKAGE, `1` tool error.
- Rule codes are stable strings; comments are generated from them, never from model text.
- Verdict rules: any blocker → `REFUSE`; packaging findings and no blocker → `REPACKAGE`; otherwise `SIGN`.

## Review Focus

- A zip with 65 000 entries or a 10 000:1 ratio must abort fast and return `REFUSE`, not exhaust memory or CPU.
- Windows-style `..\` and non-UTF-8 entry names must be normalised before traversal checks; missing this signs a traversing archive.
- A 20 MB minified `.js` must yield `NEEDS_HUMAN` from the bundle cap, never a silently truncated sample that looks reviewed.
- Duplicate entry names with different content must be a blocker; `archive/zip` last-wins would otherwise audit the wrong bytes.
- A `mod.json` with a non-numeric version must not be eligible for repackage; the bump rule must refuse to guess.

## Phase Roadmap

| Plan | Scope |
|---|---|
| `.docs/plan/01-audit-cli.md` (this) | Deterministic audit, verdict, report, bundle |
| `.docs/plan/02-signing.md` | Key discovery, minisign sign/verify, TTY approval |
| `.docs/plan/03-manager-api.md` | `../modio-manager` schema, scopes, endpoints, UI, trust store |
| `.docs/plan/04-repackage-publish.md` | archivebuild rebuild, upload, `metadata_blob` |
| `.docs/plan/05-skill-eval.md` | Skill contract, eval corpus, token budget tests |

---

### Task 1: Module, config and git baseline

**Files:**
- Create: `go.mod`, `.gitignore`, `config.toml.example`
- Create: `internal/config/config.go`, `internal/config/config_test.go`
- Create: `cmd/modaudit/main.go`

**Interfaces:**
- Produces: `config.Config`, `config.Limits`, `config.Load(path string) (config.Config, error)`, `config.Default() config.Config`.
- Produces: `package main` that prints usage and exits `1` for unknown commands.

- [ ] **Step 1: Initialise the repo and commit the docs**

```bash
cd /Users/stan/Dev/mod-signing-bench
git init
git add .docs 0ad.wiki .gitignore
git commit -m "docs: design, decisions and context"
```

The directory currently sits untracked inside the `/Users/stan/Dev` repo; this makes it its own repo. `.ref/` stays untracked.

- [ ] **Step 2: Write the failing config test**

```go
// internal/config/config_test.go
func TestLoadReadsAlphaAndLimits(t *testing.T) {
    dir := t.TempDir()
    path := filepath.Join(dir, "config.toml")
    os.WriteFile(path, []byte("target_alpha = \"0.28.0\"\n[limits]\nmax_entries = 1234\n"), 0o600)

    cfg, err := Load(path)
    if err != nil { t.Fatal(err) }
    if cfg.TargetAlpha != "0.28.0" { t.Fatalf("alpha = %q", cfg.TargetAlpha) }
    if cfg.Limits.MaxEntries != 1234 { t.Fatalf("entries = %d", cfg.Limits.MaxEntries) }
    if cfg.Limits.MaxBundleBytes != 200*1024 { t.Fatalf("default bundle cap lost: %d", cfg.Limits.MaxBundleBytes) }
}

func TestLoadMissingFileReturnsDefaults(t *testing.T) {
    cfg, err := Load(filepath.Join(t.TempDir(), "nope.toml"))
    if err != nil { t.Fatal(err) }
    if cfg.Limits.MaxEntries != 10000 { t.Fatalf("entries = %d", cfg.Limits.MaxEntries) }
}
```

- [ ] **Step 3: Run it to verify it fails**

Run: `go test ./internal/config -run TestLoad -v`
Expected: build failure, `Load` undefined.

- [ ] **Step 4: Implement `config`**

```go
type Limits struct {
    MaxEntries       int     `toml:"max_entries"`
    MaxUncompressed  int64   `toml:"max_uncompressed"`
    MaxRatio         float64 `toml:"max_ratio"`
    MaxFileSize      int64   `toml:"max_file_size"`
    MaxScriptBytes   int64   `toml:"max_script_bytes"`
    MaxBundleBytes   int     `toml:"max_bundle_bytes"`
    MaxBundleFiles   int     `toml:"max_bundle_files"`
}

type Config struct {
    ManagerURL        string   `toml:"manager_url"`
    TargetAlpha       string   `toml:"target_alpha"`
    KeyDir            string   `toml:"key_dir"`
    Pyrogenesis       string   `toml:"pyrogenesis"`
    ArchivebuildFlags []string `toml:"archivebuild_flags"`
    APIKeyFile        string   `toml:"api_key_file"`
    APIKeyCmd         string   `toml:"api_key_cmd"`
    VaultCmd          string   `toml:"vault_cmd"`
    Limits            Limits   `toml:"limits"`
}
```

`Load` starts from `Default()`, returns defaults when the file does not exist, and decodes over them with `toml.DecodeFile`. `Default()` sets every cap from Global Constraints.

- [ ] **Step 5: Run the config tests**

Run: `go test ./internal/config -v`
Expected: PASS.

- [ ] **Step 6: Add the CLI skeleton and commit**

`main.go` switches on `os.Args[1]`; `audit` is a stub returning exit `1` with "not implemented"; unknown command prints usage.

```bash
git add go.mod go.sum .gitignore config.toml.example cmd internal/config
git commit -m "feat: module scaffold and config"
```

---

### Task 2: Zip inventory

**Files:**
- Create: `internal/audit/model.go`, `internal/audit/inventory.go`
- Create: `internal/audit/fixtures_test.go`, `internal/audit/inventory_test.go`

**Interfaces:**
- Produces: `audit.Kind`, `audit.Entry`, `audit.Scan`, `audit.Limits`, `audit.Inventory(ctx context.Context, path string, lim Limits) (*Scan, error)`.
- `Scan` fields: `Path`, `Slug`, `ZipSHA256`, `Entries []Entry`, `TotalUncompressed int64`, `ModJSONRaw []byte`, `Findings []Finding`, `Aborted bool`, `AbortCode string`.
- `Entry` fields: `Name`, `Size`, `CompressedSize int64`, `Mode fs.FileMode`, `SHA256 string`, `Kind Kind`, `Link string`, `Truncated bool`.

- [ ] **Step 1: Write the fixture helper**

```go
// internal/audit/fixtures_test.go
func writeZip(t *testing.T, entries ...zipEntry) string
type zipEntry struct { name, body string; mode fs.FileMode; flags uint16 }
```

Builds a temp `.zip` with `archive/zip`, setting `FileHeader.Name`, `Method = zip.Deflate`, `Mode`, `Flags`. Returns the path.

- [ ] **Step 2: Write the failing inventory test**

```go
func TestInventoryHashesAndClassifies(t *testing.T) {
    p := writeZip(t,
        zipEntry{name: "mod/mod.json", body: `{"name":"x"}`},
        zipEntry{name: "mod/data/a.js", body: `Engine.Crash();`},
        zipEntry{name: "mod/art/a.dds", body: "DDS "},
    )
    s, err := Inventory(context.Background(), p, Limits{MaxEntries: 100})
    if err != nil { t.Fatal(err) }
    if len(s.Entries) != 3 { t.Fatalf("entries = %d", len(s.Entries)) }
    if s.Entries[1].Kind != KindJS { t.Fatalf("kind = %q", s.Entries[1].Kind) }
    if s.Entries[1].SHA256 != fmt.Sprintf("%x", sha256.Sum256([]byte("Engine.Crash();"))) { t.Fatal("bad hash") }
    if s.ZipSHA256 == "" { t.Fatal("missing archive hash") }
}

func TestInventoryAbortsOnEntryFlood(t *testing.T) {
    p := writeZip(t, floodEntries(10001)...)
    s, err := Inventory(context.Background(), p, Limits{MaxEntries: 10000})
    if err != nil { t.Fatal(err) }
    if !s.Aborted || s.AbortCode != "ZIP_TOO_MANY_ENTRIES" { t.Fatalf("abort = %v %q", s.Aborted, s.AbortCode) }
    if len(s.Entries) > 10000 { t.Fatalf("kept %d entries", len(s.Entries)) }
}
```

- [ ] **Step 3: Run it to verify it fails**

Run: `go test ./internal/audit -run TestInventory -v`
Expected: build failure, `Inventory` undefined.

- [ ] **Step 4: Implement inventory**

Open the file, hash it with a streaming `sha256`, `Seek(0, 0)`, `zip.NewReader`. Per entry: append name, sizes, mode, link target for symlinks; classify by extension then by magic (`DDS `, `XMBF`, `PMD`, `PK\x03\x04`, `MZ`, ELF, Mach-O); hash contents through `io.LimitReader` capped at `MaxFileSize`, setting `Truncated`; keep `ModJSONRaw` only for the root `mod.json`, capped at 1 MiB.

Abort (set `Aborted`, `AbortCode`, return nil error) when entries exceed `MaxEntries`, total uncompressed exceeds `MaxUncompressed`, or in-progress ratio exceeds `MaxRatio*10`. Checks that only warn are left to Task 3.

- [ ] **Step 5: Run the tests**

Run: `go test ./internal/audit -run TestInventory -v`
Expected: PASS, entry-flood test under 2 s.

- [ ] **Step 6: Commit**

```bash
git add internal/audit
git commit -m "feat: streaming zip inventory"
```

---

### Task 3: Archive safety rules

**Files:**
- Create: `internal/audit/rules_archive.go`, `internal/audit/rules_archive_test.go`

**Interfaces:**
- Produces: `audit.NormalizeName(name string) (string, bool)` returning the cleaned name and whether it is UTF-8.
- Produces: `audit.rulesArchive(s *Scan)` registered in the rule list (Task 9).

- [ ] **Step 1: Write the failing tests**

```go
func TestArchiveTraversalAndSymlinks(t *testing.T) {
    s := &Scan{Entries: []Entry{
        {Name: "../evil.js"}, {Name: "/etc/passwd"}, {Name: `..\evil.js`},
        {Name: "mod/link", Mode: fs.ModeSymlink, Link: "/etc/passwd"},
        {Name: "mod/a.js"}, {Name: "mod/a.js"},
        {Name: string([]byte{0xff, 0xfe}) + ".js"},
    }}
    rulesArchive(s)
    want := []string{"ZIP_PATH_TRAVERSAL", "ZIP_ABSOLUTE_PATH", "ZIP_SYMLINK", "ZIP_DUPLICATE_NAME", "ZIP_NAME_ENCODING"}
    for _, code := range want {
        if !hasCode(s.Findings, code) { t.Errorf("missing %s in %+v", code, s.Findings) }
    }
}

func TestArchiveBombRatio(t *testing.T) {
    s := &Scan{Entries: []Entry{{Name: "a", Size: 50 << 20, CompressedSize: 1024}}, TotalUncompressed: 50 << 20}
    rulesArchive(s)
    if !hasCode(s.Findings, "ZIP_BOMB_RATIO") { t.Fatal(s.Findings) }
}
```

Traversal, absolute path, symlink, duplicate names and encoding are blockers; bomb ratio is a blocker; a single 70 MiB asset is a warning.

- [ ] **Step 2: Run it and confirm failure**

Run: `go test ./internal/audit -run TestArchive -v`
Expected: `rulesArchive` undefined.

- [ ] **Step 3: Implement `rulesArchive`**

Normalise `\` to `/`, strip leading `./`, `path.Clean`; flag names that escape root, start with `/` or a drive letter, or are not valid UTF-8. Duplicate detection is case-insensitive. Ratio uses `TotalUncompressed / max(1, compressed total)`; compressed total comes from summing `CompressedSize`. Also flag encrypted entries (`Flags & 0x1`) and zero-entry archives.

- [ ] **Step 4: Run the tests**

Run: `go test ./internal/audit -run TestArchive -v`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add internal/audit/rules_archive.go internal/audit/rules_archive_test.go
git commit -m "feat: archive safety rules"
```

---

### Task 4: Layout rules

**Files:**
- Create: `internal/audit/rules_layout.go`, `internal/audit/rules_layout_test.go`

**Interfaces:**
- Produces: `audit.rulesLayout(s *Scan)`, producing `LAYOUT_*` findings.

- [ ] **Step 1: Write the failing tests**

```go
func TestLayoutDetectsWrapperAndJunk(t *testing.T) {
    s := &Scan{Entries: []Entry{
        {Name: "MyMod/mod.json"}, {Name: "MyMod/.DS_Store"},
        {Name: "__MACOSX/._x"}, {Name: "MyMod/.git/config"},
        {Name: "MyMod/backup.zip"}, {Name: "MyMod/file.js~"},
    }}
    rulesLayout(s)
    for _, code := range []string{"LAYOUT_WRAPPER_DIR", "LAYOUT_JUNK_FILE", "LAYOUT_NESTED_ARCHIVE"} {
        if !hasCode(s.Findings, code) { t.Errorf("missing %s", code) }
    }
}

func TestLayoutMissingModJSON(t *testing.T) {
    s := &Scan{Entries: []Entry{{Name: "data/a.js"}}}
    rulesLayout(s)
    if !hasCode(s.Findings, "LAYOUT_NO_MODJSON") { t.Fatal(s.Findings) }
}
```

`LAYOUT_NO_MODJSON` is a blocker. Wrapper dir, junk files and nested archives are packaging findings with severity `warn`.

- [ ] **Step 2: Run and confirm failure**

Run: `go test ./internal/audit -run TestLayout -v`

- [ ] **Step 3: Implement `rulesLayout`**

Wrapper: no root `mod.json`, every entry shares one first path segment, and that segment is not `mod.json` itself. Junk: `.DS_Store`, `Thumbs.db`, `__MACOSX/`, `.git/`, `__pycache__/`, `*~`, `.orig`, `.rej`. Nested archive: `.zip`, `.pyromod`, `.7z`, `.rar` inside the archive.

- [ ] **Step 4: Run the tests**

Run: `go test ./internal/audit -run TestLayout -v`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add internal/audit/rules_layout.go internal/audit/rules_layout_test.go
git commit -m "feat: zip layout rules"
```

---

### Task 5: `mod.json` rules

**Files:**
- Create: `internal/audit/rules_modjson.go`, `internal/audit/rules_modjson_test.go`

**Interfaces:**
- Produces: `audit.ModInfo` with `Name`, `Version`, `Label`, `Dependencies []string`, `IgnoreCompat bool`, `UnknownFields []string`.
- Produces: `audit.parseModJSON(raw []byte) (ModInfo, error)` and `audit.rulesModJSON(s *Scan)`.

- [ ] **Step 1: Write the failing tests**

```go
func TestModJSONRules(t *testing.T) {
    cases := []struct{ raw, want string }{
        {`{"name":"a"`, "MODJSON_INVALID"},
        {`{"version":"1.0"}`, "MODJSON_MISSING_FIELD"},
        {`{"name":"a","version":"banana","label":"A"}`, "MODJSON_VERSION_FORMAT"},
        {`{"name":"a","version":"1.0","label":"A","ignoreInCompatibilityChecks":true}`, "COMPAT_IGNORE_FLAG"},
        {`{"name":"wrong","version":"1.0","label":"A"}`, "MODJSON_NAME_MISMATCH"},
    }
    for _, c := range cases {
        s := &Scan{Slug: "right", ModJSONRaw: []byte(c.raw)}
        rulesModJSON(s)
        if !hasCode(s.Findings, c.want) { t.Errorf("%s: got %+v", c.want, s.Findings) }
    }
}

func TestModJSONUnknownFieldIsInfo(t *testing.T) {
    s := &Scan{ModJSONRaw: []byte(`{"name":"a","version":"1.0","label":"A","x_custom":1}`)}
    rulesModJSON(s)
    f := findCode(s.Findings, "MODJSON_UNKNOWN_FIELD")
    if f == nil || f.Severity != SeverityInfo { t.Fatalf("got %+v", s.Findings) }
}
```

Invalid JSON, missing `name`/`version`/`label`, and `ignoreInCompatibilityChecks` are blockers. Version format and name mismatch are warnings. Unknown fields are info.

- [ ] **Step 2: Run and confirm failure**

Run: `go test ./internal/audit -run TestModJSON -v`

- [ ] **Step 3: Implement**

Allowed fields: `name`, `version`, `label`, `description`, `dependencies`, `url`, `ignoreInCompatibilityChecks`, `minEngineVersion`, `type`. Version regex `^\d+(\.\d+)*$`. Name comparison is case-insensitive against `s.Slug` and skipped when `s.Slug` is empty. `dependencies` must be an array of strings.

- [ ] **Step 4: Run the tests**

Run: `go test ./internal/audit -run TestModJSON -v`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add internal/audit/rules_modjson.go internal/audit/rules_modjson_test.go
git commit -m "feat: mod.json validation rules"
```

---

### Task 6: Script rules

**Files:**
- Create: `internal/audit/rules_script.go`, `internal/audit/rules_script_test.go`

**Interfaces:**
- Produces: `audit.ScriptInfo` with `Path`, `SHA256`, `Bytes int64`, `EngineCalls []string`, `Network bool`, `FileSystem bool`, `DynamicLoad bool`, `Obfuscated bool`.
- Produces: `audit.analyzeScript(path string, body []byte) ScriptInfo` and `audit.rulesScript(s *Scan, bodies map[string][]byte)`.
- Produces: `audit.LoadScriptBodies(ctx context.Context, path string, names []string, maxBytes int64) (map[string][]byte, error)` used by rules and bundle.

- [ ] **Step 1: Write the failing tests**

```go
func TestScriptSignals(t *testing.T) {
    cases := []struct{ body, want string }{
        {`eval("x")`, "SCRIPT_EVAL"},
        {`Engine.Crash()`, "SCRIPT_CRASH"},
        {`var r = new XMLHttpRequest();`, "SCRIPT_NETWORK"},
        {`Engine.WriteFile("x", "y")`, "SCRIPT_FS"},
        {`importScripts("http://x/y.js")`, "SCRIPT_DYNAMIC_LOAD"},
        {`var a="` + strings.Repeat("QUJD", 4000) + `";`, "SCRIPT_OBFUSCATED"},
    }
    for _, c := range cases {
        info := analyzeScript("a.js", []byte(c.body))
        if !info.Has(c.want) { t.Errorf("%s: %+v", c.want, info) }
    }
}

func TestBenignScriptHasNoSignals(t *testing.T) {
    info := analyzeScript("a.js", []byte(`function Init(gameState) { return gameState; }`))
    if len(info.Signals) != 0 { t.Fatalf("%+v", info.Signals) }
}
```

Signals map to findings exactly: `eval`/`Function`/string `setTimeout` → `SCRIPT_EVAL` (blocker), `Engine.Crash` → `SCRIPT_CRASH` (blocker), network → `SCRIPT_NETWORK` (warn), file API → `SCRIPT_FS` (warn), dynamic load → `SCRIPT_DYNAMIC_LOAD` (warn), heuristic obfuscation → `SCRIPT_OBFUSCATED` (warn).

- [ ] **Step 2: Run and confirm failure**

Run: `go test ./internal/audit -run TestScript -v`

- [ ] **Step 3: Implement**

Regex inventory over `body`: `\beval\s*\(`, `new\s+Function\s*\(`, `setTimeout\s*\(\s*["']`, `Engine\.Crash`, `Engine\.(Read|Write)File`, `XMLHttpRequest|fetch\s*\(|WebSocket`, `importScripts\s*\(`, `Engine\.(Load|Include)Script`. Obfuscation: any line over 4 000 chars, or > 30 % of bytes as `\x`/`\u` escapes, or a base64 run over 8 000 chars. Store signals, not matched text.

`LoadScriptBodies` opens the zip with `zip.OpenReader`, reads only requested names, caps each at `maxBytes`, errors if a name is missing.

- [ ] **Step 4: Run the tests**

Run: `go test ./internal/audit -run TestScript -v`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add internal/audit/rules_script.go internal/audit/rules_script_test.go
git commit -m "feat: script signal rules"
```

---

### Task 7: Asset and XML rules

**Files:**
- Create: `internal/audit/rules_asset.go`, `internal/audit/rules_asset_test.go`

**Interfaces:**
- Produces: `audit.rulesAsset(s *Scan, bodies map[string][]byte)` with `ASSET_*` and `XML_*` findings.

- [ ] **Step 1: Write the failing tests**

```go
func TestExecutableDisguisedAsImage(t *testing.T) {
    s := &Scan{Entries: []Entry{{Name: "art/a.png", Kind: KindBinary, SHA256: "x"}}}
    rulesAsset(s, map[string][]byte{"art/a.png": []byte("MZ\x90\x00")})
    if !hasCode(s.Findings, "ASSET_EXECUTABLE") { t.Fatal(s.Findings) }
}

func TestMalformedXML(t *testing.T) {
    s := &Scan{Entries: []Entry{{Name: "sim/a.xml", Kind: KindXML}}}
    rulesAsset(s, map[string][]byte{"sim/a.xml": []byte("<root><unclosed>")})
    if !hasCode(s.Findings, "XML_MALFORMED") { t.Fatal(s.Findings) }
}

func TestValidXMLHasNoFinding(t *testing.T) {
    s := &Scan{Entries: []Entry{{Name: "sim/a.xml", Kind: KindXML}}}
    rulesAsset(s, map[string][]byte{"sim/a.xml": []byte(`<root><a/></root>`)})
    if len(s.Findings) != 0 { t.Fatal(s.Findings) }
}
```

- [ ] **Step 2: Run and confirm failure**

Run: `go test ./internal/audit -run 'TestExecutable|TestMalformed|TestValidXML' -v`

- [ ] **Step 3: Implement**

Executable magic (PE `MZ`, ELF `\x7fELF`, Mach-O `\xfe\xed\xfa`, shell `#!`) in any entry whose extension is not itself executable is `ASSET_EXECUTABLE` (blocker). An executable extension (`.exe`, `.dll`, `.so`, `.dylib`, `.node`, `.bat`, `.cmd`, `.ps1`) is also a blocker. XML parsed with `xml.Decoder` and `Strict = true`, skipping `CharData`; entities are not resolved. Malformed → `XML_MALFORMED` (warn). Entries over `MaxFileSize/4` → `ASSET_OVERSIZED` (info).

- [ ] **Step 4: Run the tests**

Run: `go test ./internal/audit -run 'TestExecutable|TestMalformed|TestValidXML' -v`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add internal/audit/rules_asset.go internal/audit/rules_asset_test.go
git commit -m "feat: asset and xml rules"
```

---

### Task 8: Packaging detection

**Files:**
- Create: `internal/audit/rules_packaging.go`, `internal/audit/rules_packaging_test.go`

**Interfaces:**
- Produces: `audit.rulesPackaging(s *Scan)` producing `PACKAGE_MISSING_XMB` and `PACKAGE_SOURCE_ASSET` (warn), and `audit.PackagingIssues(s *Scan) bool`.

- [ ] **Step 1: Write the failing tests**

```go
func TestXMLWithoutXMB(t *testing.T) {
    s := &Scan{Entries: []Entry{
        {Name: "mod.json"}, {Name: "simulation/templates/a.xml"},
    }}
    rulesPackaging(s)
    if !hasCode(s.Findings, "PACKAGE_MISSING_XMB") { t.Fatal(s.Findings) }
}

func TestXMLWithXMBIsPackaged(t *testing.T) {
    s := &Scan{Entries: []Entry{
        {Name: "mod.json"}, {Name: "simulation/templates/a.xml"},
        {Name: "simulation/templates/a.xmb"},
    }}
    rulesPackaging(s)
    if hasCode(s.Findings, "PACKAGE_MISSING_XMB") { t.Fatal(s.Findings) }
}

func TestPackagingIssuesIgnoresBlockers(t *testing.T) {
    s := &Scan{Findings: []Finding{{Code: "ZIP_BOMB_RATIO", Severity: SeverityBlocker}}}
    if PackagingIssues(s) { t.Fatal("blocker counted as packaging") }
}
```

- [ ] **Step 2: Run and confirm failure**

Run: `go test ./internal/audit -run 'TestXMLWithout|TestXMLWith|TestPackagingIssues' -v`

- [ ] **Step 3: Implement**

Build a set of entry names. For each `.xml` outside `art/` and not `mod.json`, strip the extension and check for a same-path `.xmb`. A missing counterpart is a packaging finding. `PackagingIssues` returns true only when at least one `PACKAGE_*` or `LAYOUT_*` finding exists and no blocker exists.

- [ ] **Step 4: Run the tests**

Run: `go test ./internal/audit -run 'TestXML|TestPackagingIssues' -v`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add internal/audit/rules_packaging.go internal/audit/rules_packaging_test.go
git commit -m "feat: packaging detection"
```

---

### Task 9: Scan orchestration and verdict

**Files:**
- Create: `internal/audit/scan.go`, `internal/audit/scan_test.go`
- Modify: `internal/audit/model.go` (add `Verdict` field, `Finding` helpers)

**Interfaces:**
- Produces: `audit.Options` with `Slug string`, `Limits Limits`, `Baseline map[string]string`.
- Produces: `audit.Run(ctx context.Context, zipPath string, opts Options) (*Scan, error)`.
- Produces: `audit.VerdictOf(s *Scan) Verdict`, `audit.HasBlocker(s *Scan) bool`, `(*Scan).AddFinding(code string, sev Severity, file, detail string)`.

- [ ] **Step 1: Write the failing verdict matrix**

```go
func TestVerdictMatrix(t *testing.T) {
    cases := []struct{ name string; s *Scan; want Verdict }{
        {"clean", &Scan{Entries: []Entry{{Name: "mod.json"}}, ModJSONRaw: validModJSON}, VerdictSign},
        {"blocker", &Scan{Findings: []Finding{{Code: "ZIP_PATH_TRAVERSAL", Severity: SeverityBlocker}}}, VerdictRefuse},
        {"packaging", &Scan{Findings: []Finding{{Code: "PACKAGE_MISSING_XMB", Severity: SeverityWarn}}}, VerdictRepackage},
        {"aborted", &Scan{Aborted: true, AbortCode: "ZIP_TOO_MANY_ENTRIES"}, VerdictRefuse},
        {"budget", &Scan{Findings: []Finding{{Code: "BUNDLE_BUDGET_EXCEEDED", Severity: SeverityWarn}}}, VerdictNeedsHuman},
    }
    for _, c := range cases {
        if got := VerdictOf(c.s); got != c.want { t.Errorf("%s: %s", c.name, got) }
    }
}

func TestRunEndToEndRepackage(t *testing.T) {
    p := writeZip(t,
        zipEntry{name: "MyMod/mod.json", body: `{"name":"mymod","version":"1.0","label":"My Mod"}`},
        zipEntry{name: "MyMod/simulation/templates/a.xml", body: `<root/>`},
        zipEntry{name: "MyMod/.DS_Store", body: "junk"},
    )
    s, err := Run(context.Background(), p, Options{Slug: "mymod", Limits: testLimits()})
    if err != nil { t.Fatal(err) }
    if s.Verdict != VerdictRepackage { t.Fatalf("verdict = %s findings = %+v", s.Verdict, s.Findings) }
}
```

- [ ] **Step 2: Run and confirm failure**

Run: `go test ./internal/audit -run 'TestVerdict|TestRun' -v`

- [ ] **Step 3: Implement**

`Run`: inventory → abort check → load script bodies for every `KindJS` entry (cap `MaxScriptBytes`) → apply `rulesArchive`, `rulesLayout`, `rulesModJSON`, `rulesScript`, `rulesAsset`, `rulesPackaging` in that order → sort findings by severity, code, file → set `Verdict = VerdictOf(s)`.

`VerdictOf`: aborted or any blocker → `REFUSE`; `BUNDLE_BUDGET_EXCEEDED` → `NEEDS_HUMAN`; packaging finding or `PackagingIssues` → `REPACKAGE`; else `SIGN`.

- [ ] **Step 4: Run the tests**

Run: `go test ./internal/audit -v`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add internal/audit
git commit -m "feat: scan orchestration and verdict"
```

---

### Task 10: Report and comment bullets

**Files:**
- Create: `internal/report/report.go`, `internal/report/comment.go`
- Create: `internal/report/report_test.go`, `internal/report/comment_test.go`

**Interfaces:**
- Consumes: `*audit.Scan`, `audit.Finding`.
- Produces: `report.Report` with `SchemaVersion int`, `Slug`, `ZipSHA256`, `Verdict audit.Verdict`, `ModJSON audit.ModInfo`, `Findings []audit.Finding`, `Entries []audit.Entry`, `Stats`, `Manifest map[string]string`.
- Produces: `report.Build(s *audit.Scan) Report`, `report.Serialize(r Report) ([]byte, error)`, `report.Bullets(r Report, max int) []string`.

- [ ] **Step 1: Write the failing tests**

```go
func TestBuildManifestAndStats(t *testing.T) {
    s := &audit.Scan{ZipSHA256: "abc", Verdict: audit.VerdictRefuse, Entries: []audit.Entry{
        {Name: "mod.json", Size: 10, SHA256: "h1"},
        {Name: "a.js", Size: 20, SHA256: "h2"},
        {Name: "a.xml", Size: 30, SHA256: "h3"},
    }}
    r := report.Build(s)
    if r.Manifest["a.js"] != "h2" { t.Fatalf("%+v", r.Manifest) }
    if r.Stats.JavaScriptBytes != 20 || r.Stats.XMLBytes != 30 { t.Fatalf("%+v", r.Stats) }
}

func TestBulletsAreStableAndCapped(t *testing.T) {
    r := report.Report{Findings: []audit.Finding{
        {Code: "ZIP_SYMLINK", Severity: audit.SeverityBlocker, File: "a"},
        {Code: "ZIP_SYMLINK", Severity: audit.SeverityBlocker, File: "b"},
        {Code: "MODJSON_VERSION_FORMAT", Severity: audit.SeverityWarn},
    }}
    got := report.Bullets(r, 2)
    if len(got) != 2 { t.Fatalf("%v", got) }
    if got[0] != got[0] || !strings.Contains(got[0], "symlink") { t.Fatalf("%v", got) }
    if again := report.Bullets(r, 2); !slices.Equal(got, again) { t.Fatal("unstable") }
}
```

Bullets are one per rule code (with file count in parentheses when repeated), sorted by severity then code, truncated to `max`, and end with `(+N more problems)` when truncated.

- [ ] **Step 2: Run and confirm failure**

Run: `go test ./internal/report -run 'TestBuild|TestBullets' -v`

- [ ] **Step 3: Implement**

`Report` JSON tags use snake_case; `SchemaVersion = 1`. Comments keyed by code in a `map[string]string`; a missing code falls back to a generic sentence containing the code. Include `ZIP_TOO_MANY_ENTRIES`, `ZIP_BOMB_RATIO`, `ZIP_PATH_TRAVERSAL`, `ZIP_SYMLINK`, `ZIP_DUPLICATE_NAME`, `ZIP_NAME_ENCODING`, `ZIP_ABSOLUTE_PATH`, `LAYOUT_NO_MODJSON`, `LAYOUT_WRAPPER_DIR`, `LAYOUT_JUNK_FILE`, `LAYOUT_NESTED_ARCHIVE`, `MODJSON_INVALID`, `MODJSON_MISSING_FIELD`, `MODJSON_NAME_MISMATCH`, `MODJSON_VERSION_FORMAT`, `COMPAT_IGNORE_FLAG`, `SCRIPT_EVAL`, `SCRIPT_CRASH`, `SCRIPT_NETWORK`, `SCRIPT_FS`, `SCRIPT_DYNAMIC_LOAD`, `SCRIPT_OBFUSCATED`, `ASSET_EXECUTABLE`, `XML_MALFORMED`, `PACKAGE_MISSING_XMB`, `BUNDLE_BUDGET_EXCEEDED`.

`Serialize` uses `json.MarshalIndent` with two spaces and rejects a report whose verdict is empty.

- [ ] **Step 4: Run the tests**

Run: `go test ./internal/report -v`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add internal/report
git commit -m "feat: report and comment bullets"
```

---

### Task 11: LLM bundle with caps

**Files:**
- Create: `internal/bundle/bundle.go`, `internal/bundle/bundle_test.go`

**Interfaces:**
- Produces: `bundle.Bundle` with `SchemaVersion int`, `ModJSON json.RawMessage`, `Findings []audit.Finding`, `Files []bundle.File`, `ManifestDiff []string`, `ReportDigest string`.
- Produces: `bundle.File` with `Path`, `Kind string`, `Content string`.
- Produces: `bundle.Build(ctx context.Context, zipPath string, r report.Report, baseline map[string]string, lim config.Limits) (Bundle, error)`, `bundle.ErrBudget`.

- [ ] **Step 1: Write the failing tests**

```go
func TestBundleIncludesOnlyChangedScripts(t *testing.T) {
    p := writeZip(t, zipEntry{name: "a.js", body: "Engine.Crash();"}, zipEntry{name: "b.js", body: "ok();"})
    r := report.Report{Manifest: map[string]string{"a.js": "new", "b.js": "same"}}
    b, err := bundle.Build(context.Background(), p, r, map[string]string{"a.js": "old", "b.js": "same"}, bundleLimits())
    if err != nil { t.Fatal(err) }
    if len(b.Files) != 1 || b.Files[0].Path != "a.js" { t.Fatalf("%+v", b.Files) }
    if !strings.Contains(b.Files[0].Content, "Engine.Crash") { t.Fatal("content missing") }
}

func TestBundleBudgetIsAnError(t *testing.T) {
    p := writeZip(t, zipEntry{name: "big.js", body: strings.Repeat("x", 4096)})
    r := report.Report{Manifest: map[string]string{"big.js": "h"}}
    _, err := bundle.Build(context.Background(), p, r, nil, bundleLimitsWith(1024, 10))
    if !errors.Is(err, bundle.ErrBudget) { t.Fatalf("err = %v", err) }
}
```

- [ ] **Step 2: Run and confirm failure**

Run: `go test ./internal/bundle -run TestBundle -v`

- [ ] **Step 3: Implement**

Select entries whose `Kind` is `KindJS` or (`KindXML` and path contains `simulation/`) and whose hash differs from baseline (missing baseline entry counts as changed). Read bodies with `audit.LoadScriptBodies` capped at `MaxScriptBytes`. Add files until `MaxBundleFiles` or `MaxBundleBytes` would be exceeded; return `ErrBudget` rather than truncating. `ManifestDiff` lists added/changed/removed paths, sorted. `ReportDigest` is the SHA-256 of the serialised report.

- [ ] **Step 4: Run the tests**

Run: `go test ./internal/bundle -v`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add internal/bundle
git commit -m "feat: capped llm bundle"
```

---

### Task 12: `modaudit audit` command

**Files:**
- Modify: `cmd/modaudit/main.go`
- Create: `cmd/modaudit/main_test.go`
- Create: `internal/audit/golden_test.go`, `testdata/golden/repackage-report.json`

**Interfaces:**
- Consumes: everything above.
- Produces: `modaudit audit --zip PATH [--slug S] [--baseline FILE] [--out FILE] [--bundle FILE] [--config FILE]`.

- [ ] **Step 1: Write the failing CLI test**

```go
func TestAuditExitCodes(t *testing.T) {
    clean := fixtureZip(t, `{"name":"m","version":"1.0","label":"M"}`)
    code := run([]string{"audit", "--zip", clean, "--slug", "m"})
    if code != 0 { t.Fatalf("clean exit = %d", code) }

    bad := fixtureZip(t, `{"name":"m","version":"1.0","label":"M","ignoreInCompatibilityChecks":true}`)
    if got := run([]string{"audit", "--zip", bad, "--slug", "m"}); got != 2 { t.Fatalf("refuse exit = %d", got) }
}
```

`run(args []string) int` is the testable entry point; `main` calls `os.Exit(run(os.Args[1:]))`.

- [ ] **Step 2: Run and confirm failure**

Run: `go test ./cmd/modaudit -v`

- [ ] **Step 3: Implement the command**

Parse with `flag.NewFlagSet("audit", flag.ContinueOnError)`. Load config (`--config`, then `MOD_AUDIT_CONFIG`, then `config.toml`, then defaults). Run `audit.Run`. Build report. If `--bundle`, build the bundle with the baseline; on `ErrBudget`, append `BUNDLE_BUDGET_EXCEEDED` and set `NEEDS_HUMAN`. Write `--out` (default `report.json`) and `--bundle` when asked. Print verdict, zip hash, bullets, and next command (`modaudit sign --report …`). Exit per the Global Constraints map.

- [ ] **Step 4: Add the golden fixture test**

Build the wrapper/junk/missing-XMB zip from Task 9, run `audit.Run`, `report.Build`, `report.Serialize`, compare against `testdata/golden/repackage-report.json` modulo the temp path. Regeneration is `go test ./internal/audit -run TestGoldenRepackage -update`.

- [ ] **Step 5: Run all tests**

Run: `go test ./...`
Expected: PASS.

- [ ] **Step 6: Commit**

```bash
git add cmd internal testdata
git commit -m "feat: audit command with exit codes"
```

---

### Task 13: Fuzzing, vet and usage docs

**Files:**
- Create: `internal/audit/fuzz_test.go`
- Create: `README.md`
- Modify: `.docs/context.md` (add build/test commands)

- [ ] **Step 1: Write the fuzz tests**

```go
func FuzzNormalizeName(f *testing.F) {
    for _, s := range []string{"a/b", "../x", `a\b`, "/abs", string([]byte{0xff})} { f.Add(s) }
    f.Fuzz(func(t *testing.T, name string) {
        norm, utf8OK := NormalizeName(name)
        if norm != "" && path.IsAbs(norm) { t.Fatalf("absolute survived: %q", norm) }
        _ = utf8OK
    })
}

func FuzzRunOnArbitraryBytes(f *testing.F) {
    f.Add([]byte("PK\x03\x04"))
    f.Fuzz(func(t *testing.T, data []byte) {
        p := filepath.Join(t.TempDir(), "m.zip")
        os.WriteFile(p, data, 0o600)
        _, _ = Run(context.Background(), p, Options{Limits: testLimits()})
    })
}
```

The second must never panic, never hang past 5 s, and never write outside its temp dir.

- [ ] **Step 2: Run them**

Run: `go test ./internal/audit -run '^$' -fuzz FuzzRunOnArbitraryBytes -fuzztime 20s`
Expected: no panic; `ok` or only seed-corpus failures that are fixed.

- [ ] **Step 3: Run vet and the full suite**

Run: `go vet ./... && go test ./...`
Expected: clean, PASS.

- [ ] **Step 4: Write `README.md`**

Usage of `modaudit audit`, the verdict/exit-code table, config keys, what the tool does not do (no signing, no network, no LLM), and where the design lives.

- [ ] **Step 5: Commit**

```bash
git add internal/audit/fuzz_test.go README.md .docs/context.md
git commit -m "test: fuzz zip parsing; docs: audit usage"
```

---

## Self-Review

- **Spec coverage (Phase 1):** design §9 rules → Tasks 2–8; §8 verdicts → Task 9; §10 bundle → Task 11; §14 bullets → Task 10; §17 tests → Tasks 3–13. Signing, manager, repackage and skill are explicitly deferred to plans 02–05.
- **Types consistent:** `audit.Scan`/`Entry`/`Finding` defined in Task 2, extended in Task 9; `report.Report` consumes them; `bundle` consumes `report.Report` and `config.Limits`.
- **Review Focus tests:** entry flood → Task 2; backslash/non-UTF-8 → Task 3 fuzz + tests; huge JS → Task 11 budget test; duplicate names → Task 3; non-numeric version → Task 5.
- **Proportion:** rule bodies are described, not transcribed; tests carry the exact values.
- **Gap found and fixed:** `NEEDS_HUMAN` had no producer in the first draft; Task 11 and Task 12 now produce it from `ErrBudget`.
