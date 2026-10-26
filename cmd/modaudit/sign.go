package main

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

	"aead.dev/minisign"

	"github.com/stan/modaudit/internal/approval"
	"github.com/stan/modaudit/internal/audit"
	"github.com/stan/modaudit/internal/blob"
	"github.com/stan/modaudit/internal/config"
	"github.com/stan/modaudit/internal/keys"
	"github.com/stan/modaudit/internal/report"
	"github.com/stan/modaudit/internal/signer"
	"github.com/stan/modaudit/internal/trust"
)

type signDeps struct {
	openTerminal func() (approval.Terminal, error)
}

func sha256File(p string) (string, error) {
	f, err := os.Open(p)
	if err != nil {
		return "", err
	}
	defer f.Close()
	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		return "", err
	}
	return hex.EncodeToString(h.Sum(nil)), nil
}

func runSign(args []string, deps signDeps) int {
	if deps.openTerminal == nil {
		deps.openTerminal = approval.Open
	}
	fs := flag.NewFlagSet("sign", flag.ContinueOnError)
	reportPath := fs.String("report", "", "")
	zipPath := fs.String("zip", "", "")
	alpha := fs.String("alpha", "", "")
	mergeBlob := fs.String("merge-blob", "", "")
	passwordCmd := fs.String("password-cmd", "", "")
	outDir := fs.String("out-dir", "", "")
	configPath := fs.String("config", "", "")
	if err := fs.Parse(args); err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 1
	}
	if *reportPath == "" || *zipPath == "" {
		fmt.Fprintln(os.Stderr, "missing --report or --zip")
		return 1
	}

	cfg, err := config.Load(*configPath)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 1
	}
	if cfg.KeyDir == "" || cfg.TargetAlpha == "" {
		fmt.Fprintln(os.Stderr, "missing key_dir or target_alpha")
		return 2
	}
	if _, ok := trust.ForAlpha(cfg.TargetAlpha); !ok {
		fmt.Fprintln(os.Stderr, "unknown target_alpha")
		return 2
	}

	rb, err := os.ReadFile(*reportPath)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 1
	}
	var rep report.Report
	if err := json.Unmarshal(rb, &rep); err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 1
	}
	if rep.SchemaVersion != 1 || rep.Verdict != "SIGN" {
		fmt.Fprintln(os.Stderr, "report not signable")
		return 2
	}

	sha, err := sha256File(*zipPath)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 1
	}
	if !strings.EqualFold(sha, rep.ZipSHA256) {
		fmt.Fprintln(os.Stderr, "zip hash mismatch")
		return 2
	}

	if *alpha != "" && *alpha != cfg.TargetAlpha {
		fmt.Fprintln(os.Stderr, "alpha mismatch")
		return 2
	}

	k, err := keys.Select(cfg.KeyDir, cfg.TargetAlpha)
	if err != nil {
		if errors.Is(err, keys.ErrNoKey) {
			fmt.Fprintln(os.Stderr, "no key for alpha")
			return 2
		}
		fmt.Fprintln(os.Stderr, err)
		return 1
	}

	var oldBlob blob.Blob
	if *mergeBlob != "" {
		mb, err := os.ReadFile(*mergeBlob)
		if err != nil {
			fmt.Fprintln(os.Stderr, err)
			return 1
		}
		oldBlob, err = blob.Parse(mb)
		if err != nil {
			fmt.Fprintln(os.Stderr, err)
			return 1
		}
		if _, err := blob.Validate(oldBlob, *zipPath); err != nil {
			fmt.Fprintln(os.Stderr, err)
			return 2
		}
	}
	if !audit.EngineAdmits(rep.ModJSON.Dependencies, cfg.TargetAlpha) {
		fmt.Fprintln(os.Stderr, "engine dependency mismatch")
		return 2
	}
	for _, es := range oldBlob.Minisigs {
		es2 := strings.ReplaceAll(es, "\r", "")
		es2 = strings.TrimRight(es2, "\n")
		var sigobj minisign.Signature
		if err := sigobj.UnmarshalText([]byte(es2)); err == nil {
			if k2, ok := trust.ByID(sigobj.KeyID); ok {
				for _, a := range k2.Alphas {
					if !audit.EngineAdmits(rep.ModJSON.Dependencies, a) {
						fmt.Fprintln(os.Stderr, "engine dependency mismatch")
						return 2
					}
				}
			}
		}
	}

	term, err := deps.openTerminal()
	if err != nil {
		if errors.Is(err, approval.ErrNoTerminal) {
			fmt.Fprintln(os.Stderr, "no terminal")
			return 2
		}
		fmt.Fprintln(os.Stderr, err)
		return 1
	}
	defer term.Close()

	summary := []string{
		"slug: " + rep.Slug,
		"name: " + rep.ModJSON.Name + " version: " + rep.ModJSON.Version,
		"deps: " + strings.Join(rep.ModJSON.Dependencies, ","),
		"zip: " + *zipPath,
		"sha256: " + sha,
		"alpha: " + cfg.TargetAlpha,
		"key: " + k.Path,
	}
	token := sha
	if len(token) > 12 {
		token = token[:12]
	}
	ok, err := approval.Confirm(term, summary, token)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 1
	}
	if !ok {
		fmt.Fprintln(os.Stderr, "declined")
		return 3
	}

	passCmd := *passwordCmd
	if passCmd == "" {
		passCmd = cfg.VaultCmd
	}
	pw, err := approval.Password(term, passCmd, filepath.Base(k.Path))
	if err != nil {
		fmt.Fprintln(os.Stderr, "cannot decrypt "+filepath.Base(k.Path))
		return 1
	}
	defer func() {
		for i := range pw {
			pw[i] = 0
		}
	}()

	keyRaw, err := os.ReadFile(k.Path)
	if err != nil {
		fmt.Fprintln(os.Stderr, "cannot decrypt "+filepath.Base(k.Path))
		return 1
	}
	priv, err := minisign.DecryptKey(string(pw), keyRaw)
	if err != nil {
		fmt.Fprintln(os.Stderr, "cannot decrypt "+filepath.Base(k.Path))
		return 1
	}

	res, err := signer.Sign(signer.Request{ZipPath: *zipPath, WantSHA256: sha, Alpha: cfg.TargetAlpha, Key: priv})
	if err != nil {
		if errors.Is(err, signer.ErrWrongKey) || errors.Is(err, signer.ErrHashMismatch) {
			fmt.Fprintln(os.Stderr, err)
			return 2
		}
		fmt.Fprintln(os.Stderr, err)
		return 1
	}

	newBlob, err := blob.Merge(oldBlob, rep.ModJSON.Dependencies, res.Signature, *zipPath)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 1
	}

	od := *outDir
	if od == "" {
		od = filepath.Dir(*zipPath)
	}
	base := filepath.Base(*zipPath)
	sigPath := filepath.Join(od, base+".minisig")
	blobPath := filepath.Join(od, base+".blob.json")
	if _, err := os.Stat(sigPath); err == nil {
		fmt.Fprintln(os.Stderr, "refusing to overwrite existing .minisig")
		return 1
	}
	if err := os.WriteFile(sigPath, append(res.Signature, '\n'), 0o644); err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 1
	}
	mb, err := blob.Marshal(newBlob)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 1
	}
	if err := os.WriteFile(blobPath, append(mb, '\n'), 0o644); err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 1
	}

	fmt.Printf("keyid %x\nsig %s\nblob %s\n", res.KeyID, sigPath, blobPath)
	return 0
}
