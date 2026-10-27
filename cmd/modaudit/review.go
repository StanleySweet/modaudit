package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"aead.dev/minisign"

	"github.com/stan/modaudit/internal/approval"
	"github.com/stan/modaudit/internal/audit"
	"github.com/stan/modaudit/internal/blob"
	"github.com/stan/modaudit/internal/config"
	"github.com/stan/modaudit/internal/keys"
	"github.com/stan/modaudit/internal/manager"
	"github.com/stan/modaudit/internal/signer"
	"github.com/stan/modaudit/internal/trust"
)

type reviewDeps struct {
	openTerminal func() (approval.Terminal, error)
}

// reviewer walks audited tasks; every write to mod.io needs an answer on the terminal.
type reviewer struct {
	ctx    context.Context
	cfg    config.Config
	client *manager.Client
	term   approval.Terminal
	key    *minisign.PrivateKey // decrypted once per session, on the first signature
}

func runReview(args []string, deps reviewDeps) int {
	if deps.openTerminal == nil {
		deps.openTerminal = approval.Open
	}
	fs := flag.NewFlagSet("review", flag.ContinueOnError)
	configPath := fs.String("config", "", "config.toml path")
	if err := fs.Parse(args); err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 1
	}
	cfg, err := loadConfig(*configPath)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 1
	}
	if cfg.ManagerURL == "" {
		fmt.Fprintln(os.Stderr, "missing manager_url")
		return 2
	}
	apiKey, err := resolveAPIKey(cfg)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 2
	}
	term, err := deps.openTerminal()
	if err != nil {
		fmt.Fprintln(os.Stderr, "review needs an interactive terminal")
		return 2
	}
	defer term.Close()

	r := &reviewer{ctx: context.Background(), cfg: cfg, client: manager.NewClient(cfg.ManagerURL, apiKey), term: term}
	reviews, err := r.client.Reviews(r.ctx)
	if err != nil {
		fmt.Fprintln(os.Stderr, "reviews:", err)
		return 1
	}
	if len(reviews) == 0 {
		term.Println("Nothing to review.")
		return 0
	}
	for i, rv := range reviews {
		term.Println("")
		term.Println(fmt.Sprintf("[%d/%d] %s %s: %s", i+1, len(reviews), rv.Name, rv.Version, rv.Verdict))
		term.Println("  " + rv.ModIOURL)
		if codes := findingCodes(rv.Findings); codes != "" {
			term.Println("  findings: " + codes)
		}
		if rv.PreviousError != "" {
			term.Println("  previous attempt failed: " + rv.PreviousError)
		}
		var err error
		if rv.Verdict == string(audit.VerdictSign) {
			err = r.sign(rv)
		} else {
			err = r.other(rv)
		}
		if err != nil {
			term.Println("  error: " + err.Error())
		}
	}
	return 0
}

// choose asks until the answer is one of options; empty input picks def.
func (r *reviewer) choose(prompt string, options string, def byte) (byte, error) {
	for {
		line, err := r.term.ReadLine(prompt)
		if err != nil {
			return 0, err
		}
		line = strings.ToLower(strings.TrimSpace(line))
		if line == "" {
			return def, nil
		}
		if len(line) == 1 && strings.IndexByte(options, line[0]) >= 0 {
			return line[0], nil
		}
	}
}

func (r *reviewer) other(rv manager.Review) error {
	if rv.CommentDraft != "" {
		r.term.Println("  comment draft:")
		for _, l := range strings.Split(rv.CommentDraft, "\n") {
			r.term.Println("    " + l)
		}
	}
	if rv.Verdict == string(audit.VerdictRefuse) && rv.CommentDraft != "" {
		c, err := r.choose("  [c]omment on mod.io, [d]ismiss, [S]kip: ", "cds", 's')
		if err != nil || c == 's' {
			return err
		}
		if c == 'c' {
			if err := r.client.Comment(r.ctx, rv.TaskID); err != nil {
				return err
			}
			r.term.Println("  comment posted")
			return nil
		}
	} else {
		c, err := r.choose("  [d]ismiss, [S]kip: ", "ds", 's')
		if err != nil || c == 's' {
			return err
		}
	}
	if err := r.client.Dismiss(r.ctx, rv.TaskID); err != nil {
		return err
	}
	r.term.Println("  dismissed")
	return nil
}

func (r *reviewer) sign(rv manager.Review) error {
	alpha := r.cfg.TargetAlpha
	if r.cfg.KeyDir == "" || alpha == "" {
		return errors.New("set key_dir and target_alpha in config.toml to sign")
	}
	if _, ok := trust.ForAlpha(alpha); !ok {
		return fmt.Errorf("unknown target_alpha %s", alpha)
	}
	if !audit.EngineAdmits(rv.ModJSON.Dependencies, alpha) {
		return fmt.Errorf("mod.json dependencies %v do not admit %s", rv.ModJSON.Dependencies, alpha)
	}
	c, err := r.choose("  [s]ign, [d]ismiss, s[K]ip: ", "sdk", 'k')
	if err != nil || c == 'k' {
		return err
	}
	if c == 'd' {
		if err := r.client.Dismiss(r.ctx, rv.TaskID); err != nil {
			return err
		}
		r.term.Println("  dismissed")
		return nil
	}

	k, err := keys.Select(r.cfg.KeyDir, alpha)
	if err != nil {
		return err
	}
	tmpDir, err := os.MkdirTemp("", "modaudit-review-")
	if err != nil {
		return err
	}
	defer os.RemoveAll(tmpDir)
	zipPath := filepath.Join(tmpDir, "mod.zip")
	r.term.Println(fmt.Sprintf("  downloading %d MB", rv.FileSize>>20))
	if err := r.client.DownloadMod(r.ctx, rv.DownloadURL, zipPath, rv.MD5); err != nil {
		return err
	}
	sha, err := sha256File(zipPath)
	if err != nil {
		return err
	}
	if !strings.EqualFold(sha, rv.ZipSHA256) {
		return errors.New("downloaded zip is not the audited zip")
	}

	summary := []string{
		"  name: " + rv.ModJSON.Name + " version: " + rv.ModJSON.Version,
		"  deps: " + strings.Join(rv.ModJSON.Dependencies, ","),
		"  sha256: " + sha,
		"  alpha: " + alpha + " key: " + filepath.Base(k.Path),
		"  This signs the file and writes the signature to mod.io.",
	}
	ok, err := approval.Confirm(r.term, summary, sha[:12])
	if err != nil {
		return err
	}
	if !ok {
		r.term.Println("  token mismatch, skipped")
		return nil
	}

	if r.key == nil {
		pw, err := approval.Password(r.term, r.cfg.VaultCmd, filepath.Base(k.Path))
		if err != nil {
			return err
		}
		keyRaw, err := os.ReadFile(k.Path)
		if err == nil {
			var priv minisign.PrivateKey
			priv, err = minisign.DecryptKey(string(pw), keyRaw)
			r.key = &priv
		}
		for i := range pw {
			pw[i] = 0
		}
		if err != nil {
			r.key = nil
			return errors.New("cannot decrypt " + filepath.Base(k.Path))
		}
	}

	res, err := signer.Sign(signer.Request{ZipPath: zipPath, WantSHA256: sha, Alpha: alpha, Key: *r.key})
	if err != nil {
		return err
	}
	// Queued versions are unsigned, so there are no earlier signatures to keep
	newBlob, err := blob.Merge(blob.Blob{}, rv.ModJSON.Dependencies, res.Signature, zipPath)
	if err != nil {
		return err
	}
	mb, err := blob.Marshal(newBlob)
	if err != nil {
		return err
	}
	if err := r.client.Publish(r.ctx, rv.TaskID, mb); err != nil {
		return err
	}
	r.term.Println("  signed; the manager verifies it and writes it to mod.io in the background")
	return nil
}

func findingCodes(fs []manager.Finding) string {
	seen := map[string]bool{}
	var codes []string
	for _, f := range fs {
		if !seen[f.Code] {
			seen[f.Code] = true
			codes = append(codes, f.Code)
		}
	}
	sort.Strings(codes)
	return strings.Join(codes, ", ")
}
