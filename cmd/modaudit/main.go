package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"os"

	"github.com/stan/modaudit/internal/audit"
	"github.com/stan/modaudit/internal/bundle"
	"github.com/stan/modaudit/internal/config"
	"github.com/stan/modaudit/internal/report"
)

const usage = `usage: modaudit <command> [flags]

commands:
  audit   audit a mod zip and write a report
`

var exitCodes = map[audit.Verdict]int{
	audit.VerdictSign:       0,
	audit.VerdictRefuse:     2,
	audit.VerdictNeedsHuman: 3,
	audit.VerdictRepackage:  4,
}

func main() {
	os.Exit(run(os.Args[1:]))
}

func run(args []string) int {
	if len(args) == 0 {
		fmt.Fprint(os.Stderr, usage)
		return 1
	}
	switch args[0] {
	case "audit":
		code, err := runAudit(args[1:])
		if err != nil {
			fmt.Fprintln(os.Stderr, "audit:", err)
			return 1
		}
		return code
	default:
		fmt.Fprintf(os.Stderr, "unknown command %q\n\n%s", args[0], usage)
		return 1
	}
}

func runAudit(args []string) (int, error) {
	fs := flag.NewFlagSet("audit", flag.ContinueOnError)
	zipPath := fs.String("zip", "", "mod zip to audit (required)")
	slug := fs.String("slug", "", "mod.io slug; checked against mod.json name")
	baselinePath := fs.String("baseline", "", "previous report.json; its manifest is the baseline")
	out := fs.String("out", "report.json", "report output path")
	bundlePath := fs.String("bundle", "", "write the LLM bundle to this path")
	configPath := fs.String("config", "", "config.toml path (default $MOD_AUDIT_CONFIG, then ./config.toml)")
	if err := fs.Parse(args); err != nil {
		return 0, err
	}
	if *zipPath == "" {
		return 0, errors.New("--zip is required")
	}

	cfg, err := loadConfig(*configPath)
	if err != nil {
		return 0, err
	}
	baseline, err := loadBaseline(*baselinePath)
	if err != nil {
		return 0, err
	}

	ctx := context.Background()
	s, err := audit.Run(ctx, *zipPath, audit.Options{Slug: *slug, Limits: audit.Limits(cfg.Limits), Baseline: baseline})
	if err != nil {
		return 0, err
	}
	r := report.Build(s)

	var b *bundle.Bundle
	if *bundlePath != "" {
		got, err := bundle.Build(ctx, *zipPath, r, baseline, cfg.Limits)
		switch {
		case errors.Is(err, bundle.ErrBudget):
			s.AddFinding("BUNDLE_BUDGET_EXCEEDED", audit.SeverityWarn, "", "changed scripts exceed the bundle caps")
			s.Verdict = audit.VerdictOf(s)
			r = report.Build(s)
		case err != nil:
			return 0, err
		default:
			b = &got
		}
	}

	data, err := report.Serialize(r)
	if err != nil {
		return 0, err
	}
	if err := os.WriteFile(*out, data, 0o644); err != nil {
		return 0, err
	}
	if b != nil {
		data, err := json.MarshalIndent(b, "", "  ")
		if err != nil {
			return 0, err
		}
		if err := os.WriteFile(*bundlePath, data, 0o644); err != nil {
			return 0, err
		}
	}

	fmt.Printf("verdict: %s\nzip sha256: %s\n", r.Verdict, r.ZipSHA256)
	for _, line := range report.Bullets(r, 10) {
		fmt.Println(line)
	}
	fmt.Println("report:", *out)
	if b != nil {
		fmt.Println("bundle:", *bundlePath)
	}
	if r.Verdict == audit.VerdictSign {
		fmt.Println("next: modaudit sign --report", *out)
	}
	return exitCodes[r.Verdict], nil
}

// loadConfig resolves --config, then MOD_AUDIT_CONFIG, then ./config.toml.
// An explicitly named file must exist; ./config.toml is optional.
func loadConfig(path string) (config.Config, error) {
	if path == "" {
		path = os.Getenv("MOD_AUDIT_CONFIG")
	}
	if path == "" {
		return config.Load("config.toml")
	}
	if _, err := os.Stat(path); err != nil {
		return config.Config{}, err
	}
	return config.Load(path)
}

func loadBaseline(path string) (map[string]string, error) {
	if path == "" {
		return nil, nil
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var prev report.Report
	if err := json.Unmarshal(data, &prev); err != nil {
		return nil, fmt.Errorf("baseline %s: %w", path, err)
	}
	return prev.Manifest, nil
}
