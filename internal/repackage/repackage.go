// Package repackage rebuilds a REPACKAGE-verdict mod with pyrogenesis
// -archivebuild: patch version bump, compiled artefacts added, nothing else.
package repackage

import (
	"archive/zip"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/stan/modaudit/internal/audit"
)

var (
	ErrVersion          = errors.New("mod.json version is not dotted numeric with at least two parts; needs a human")
	ErrUnexpectedChange = errors.New("rebuild changed more than compiled artefacts and mod.json version")
	ErrEngineVersion    = errors.New("pyrogenesis version does not match the target alpha")
)

// Options configures a rebuild.
type Options struct {
	Pyrogenesis string   // path to the pyrogenesis binary
	Flags       []string // extra archivebuild flags
	Alpha       string   // target alpha; pyrogenesis must report exactly this version
	Limits      audit.Limits
	WorkDir     string // scratch directory, owned by the caller
}

// Result is a rebuilt, re-audited zip.
type Result struct {
	ZipPath    string
	SHA256     string
	OldVersion string
	NewVersion string
	Added      []string // compiled artefacts archivebuild added
	Scan       *audit.Scan
}

// runCommand is swapped in tests.
var runCommand = func(ctx context.Context, name string, args ...string) ([]byte, error) {
	return exec.CommandContext(ctx, name, args...).CombinedOutput()
}

// fixedTime makes rebuilt zips reproducible.
var fixedTime = time.Date(2000, 1, 1, 0, 0, 0, 0, time.UTC)

var versionField = regexp.MustCompile(`("version"\s*:\s*")([^"]*)(")`)

// Rebuild extracts zipPath, bumps the mod.json patch version, runs archivebuild,
// writes a reproducible zip, checks only compiled artefacts and mod.json changed,
// and re-audits the result, which must be SIGN.
func Rebuild(ctx context.Context, zipPath string, opt Options) (Result, error) {
	if err := checkEngine(ctx, opt.Pyrogenesis, opt.Alpha); err != nil {
		return Result{}, err
	}
	src := filepath.Join(opt.WorkDir, "src")
	orig, err := extract(zipPath, src)
	if err != nil {
		return Result{}, err
	}
	oldV, newV, modJSONSHA, err := bumpVersion(filepath.Join(src, "mod.json"))
	if err != nil {
		return Result{}, err
	}
	orig["mod.json"] = modJSONSHA

	built := filepath.Join(opt.WorkDir, "built.zip")
	args := append([]string{"-archivebuild=" + src, "-archivebuild-output=" + built, "-archivebuild-compress"}, opt.Flags...)
	if out, err := runCommand(ctx, opt.Pyrogenesis, args...); err != nil {
		return Result{}, fmt.Errorf("archivebuild: %v: %s", err, tail(out))
	}
	outZip := filepath.Join(opt.WorkDir, "rebuilt.zip")
	if err := reproducible(built, outZip); err != nil {
		return Result{}, err
	}

	s, err := audit.Run(ctx, outZip, audit.Options{Limits: opt.Limits, TargetAlpha: opt.Alpha})
	if err != nil {
		return Result{}, err
	}
	added, err := compare(orig, s.Entries)
	if err != nil {
		return Result{}, err
	}
	if s.Verdict != audit.VerdictSign {
		var codes []string
		for _, f := range s.Findings {
			codes = append(codes, f.Code)
		}
		return Result{}, fmt.Errorf("rebuilt zip audits as %s (%s)", s.Verdict, strings.Join(codes, ", "))
	}
	return Result{ZipPath: outZip, SHA256: s.ZipSHA256, OldVersion: oldV, NewVersion: newV, Added: added, Scan: s}, nil
}

func checkEngine(ctx context.Context, bin, alpha string) error {
	if bin == "" {
		return errors.New("set pyrogenesis in config.toml to repackage")
	}
	out, err := runCommand(ctx, bin, "-version")
	if err != nil {
		return fmt.Errorf("pyrogenesis -version: %v", err)
	}
	f := strings.Fields(string(out))
	for i := 0; i+1 < len(f); i++ {
		if f[i] == "Pyrogenesis" && f[i+1] == alpha {
			return nil
		}
	}
	return fmt.Errorf("%w: %q, want %s", ErrEngineVersion, strings.TrimSpace(string(out)), alpha)
}

// extract writes every non-junk file under dst, strips a single wrapper
// directory and returns name -> sha256 of what was written.
func extract(zipPath, dst string) (map[string]string, error) {
	zr, err := zip.OpenReader(zipPath)
	if err != nil {
		return nil, err
	}
	defer zr.Close()

	wrapper := ""
	hasRoot := false
	for _, f := range zr.File {
		n, _ := audit.NormalizeName(f.Name)
		if n == "mod.json" {
			hasRoot = true
		} else if path.Base(n) == "mod.json" && strings.Count(n, "/") == 1 && !audit.IsJunk(n) {
			wrapper = path.Dir(n) + "/"
		}
	}
	if hasRoot {
		wrapper = ""
	}

	out := map[string]string{}
	for _, f := range zr.File {
		n, _ := audit.NormalizeName(f.Name)
		if f.FileInfo().IsDir() || n == "" || audit.IsJunk(n) {
			continue
		}
		if f.Mode()&os.ModeSymlink != 0 {
			return nil, fmt.Errorf("symlink %s", f.Name)
		}
		if wrapper != "" {
			if !strings.HasPrefix(n, wrapper) {
				return nil, fmt.Errorf("%s is outside the wrapper directory %s", f.Name, wrapper)
			}
			n = strings.TrimPrefix(n, wrapper)
		}
		if n == ".." || strings.HasPrefix(n, "../") || path.IsAbs(n) {
			return nil, fmt.Errorf("path escapes the archive root: %s", f.Name)
		}
		if _, dup := out[n]; dup {
			return nil, fmt.Errorf("duplicate entry %s", n)
		}
		sum, err := writeEntry(f, filepath.Join(dst, filepath.FromSlash(n)))
		if err != nil {
			return nil, err
		}
		out[n] = sum
	}
	if _, ok := out["mod.json"]; !ok {
		return nil, errors.New("no mod.json at the archive root")
	}
	return out, nil
}

func writeEntry(f *zip.File, p string) (string, error) {
	if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
		return "", err
	}
	rc, err := f.Open()
	if err != nil {
		return "", err
	}
	defer rc.Close()
	w, err := os.OpenFile(p, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o644)
	if err != nil {
		return "", err
	}
	h := sha256.New()
	_, err = io.Copy(io.MultiWriter(w, h), rc)
	if cerr := w.Close(); err == nil {
		err = cerr
	}
	return hex.EncodeToString(h.Sum(nil)), err
}

// bumpVersion rewrites only the version value: 1.2 -> 1.2.1, 1.2.3 -> 1.2.4.
func bumpVersion(p string) (oldV, newV, sum string, err error) {
	raw, err := os.ReadFile(p)
	if err != nil {
		return "", "", "", err
	}
	var m struct {
		Version string `json:"version"`
	}
	if err := json.Unmarshal(raw, &m); err != nil {
		return "", "", "", fmt.Errorf("mod.json: %w", err)
	}
	newV, err = NextPatch(m.Version)
	if err != nil {
		return "", "", "", err
	}
	loc := versionField.FindSubmatchIndex(raw)
	if loc == nil || string(raw[loc[4]:loc[5]]) != m.Version {
		return "", "", "", ErrVersion
	}
	out := append(append(append([]byte{}, raw[:loc[4]]...), newV...), raw[loc[5]:]...)
	if err := os.WriteFile(p, out, 0o644); err != nil {
		return "", "", "", err
	}
	h := sha256.Sum256(out)
	return m.Version, newV, hex.EncodeToString(h[:]), nil
}

// NextPatch returns the patch bump of a dotted numeric version.
func NextPatch(v string) (string, error) {
	parts := strings.Split(v, ".")
	if len(parts) < 2 {
		return "", ErrVersion
	}
	for _, p := range parts {
		if p == "" || strings.Trim(p, "0123456789") != "" {
			return "", ErrVersion
		}
	}
	if len(parts) == 2 {
		return v + ".1", nil
	}
	n, err := strconv.Atoi(parts[len(parts)-1])
	if err != nil {
		return "", ErrVersion
	}
	parts[len(parts)-1] = strconv.Itoa(n + 1)
	return strings.Join(parts, "."), nil
}

// reproducible copies src to dst with sorted entries and fixed timestamps,
// keeping the compressed bytes archivebuild produced.
func reproducible(src, dst string) error {
	zr, err := zip.OpenReader(src)
	if err != nil {
		return err
	}
	defer zr.Close()
	files := append([]*zip.File(nil), zr.File...)
	sort.Slice(files, func(i, j int) bool { return files[i].Name < files[j].Name })

	w, err := os.Create(dst)
	if err != nil {
		return err
	}
	zw := zip.NewWriter(w)
	for _, f := range files {
		h := f.FileHeader
		h.Modified = fixedTime
		h.ModifiedTime, h.ModifiedDate = 0, 0
		h.Extra = nil
		h.Comment = ""
		h.SetMode(0o644)
		raw, err := f.OpenRaw()
		if err != nil {
			w.Close()
			return err
		}
		fw, err := zw.CreateRaw(&h)
		if err != nil {
			w.Close()
			return err
		}
		if _, err := io.Copy(fw, raw); err != nil {
			w.Close()
			return err
		}
	}
	if err := zw.Close(); err != nil {
		w.Close()
		return err
	}
	return w.Close()
}

// compare allows only: unchanged originals, the bumped mod.json (already in orig),
// and new "<original>.cached.<ext>" artefacts.
func compare(orig map[string]string, rebuilt []audit.Entry) ([]string, error) {
	seen := map[string]bool{}
	var added, problems []string
	for _, e := range rebuilt {
		if strings.HasSuffix(e.Name, "/") {
			continue
		}
		seen[e.Name] = true
		if want, ok := orig[e.Name]; ok {
			if want != e.SHA256 {
				problems = append(problems, "changed "+e.Name)
			}
			continue
		}
		if i := strings.LastIndex(e.Name, ".cached."); i > 0 {
			if _, ok := orig[e.Name[:i]]; ok {
				added = append(added, e.Name)
				continue
			}
		}
		problems = append(problems, "added "+e.Name)
	}
	for n := range orig {
		if !seen[n] {
			problems = append(problems, "removed "+n)
		}
	}
	if len(problems) > 0 {
		sort.Strings(problems)
		if len(problems) > 10 {
			problems = append(problems[:10], fmt.Sprintf("and %d more", len(problems)-10))
		}
		return nil, fmt.Errorf("%w: %s", ErrUnexpectedChange, strings.Join(problems, "; "))
	}
	sort.Strings(added)
	return added, nil
}

func tail(b []byte) string {
	s := strings.TrimSpace(string(b))
	if len(s) > 500 {
		s = "..." + s[len(s)-500:]
	}
	return s
}
