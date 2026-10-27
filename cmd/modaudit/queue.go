package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"strings"
	"time"

	"aead.dev/minisign"

	"github.com/stan/modaudit/internal/approval"
	"github.com/stan/modaudit/internal/audit"
	"github.com/stan/modaudit/internal/blob"
	"github.com/stan/modaudit/internal/config"
	"github.com/stan/modaudit/internal/keys"
	"github.com/stan/modaudit/internal/manager"
	"github.com/stan/modaudit/internal/report"
	"github.com/stan/modaudit/internal/signer"
	"github.com/stan/modaudit/internal/trust"
)

type queueDeps struct {
	openTerminal func() (approval.Terminal, error)
}

func resolveAPIKey(cfg config.Config) (string, error) {
	if cfg.APIKeyFile != "" {
		b, err := os.ReadFile(cfg.APIKeyFile)
		if err != nil {
			return "", err
		}
		return strings.TrimSpace(string(b)), nil
	}
	if v := os.Getenv("MOD_AUDIT_MANAGER_API_KEY"); v != "" {
		return v, nil
	}
	return "", errors.New("no manager api key configured (api_key_file/api_key_cmd)")
}

func runProcessQueue(args []string, deps queueDeps) int {
	if deps.openTerminal == nil {
		deps.openTerminal = approval.Open
	}
	fs := flag.NewFlagSet("process-queue", flag.ContinueOnError)
	interval := fs.Int("interval", 30, "poll interval seconds")
	once := fs.Bool("once", false, "process one task and exit")
	verbose := fs.Bool("verbose", false, "verbose")
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

	client := manager.NewClient(cfg.ManagerURL, apiKey)
	ctx := context.Background()

	for {
		task, err := client.NextTask(ctx)
		if err != nil {
			if errors.Is(err, manager.ErrNoTask) {
				if *once {
					return 0
				}
				if *verbose {
					log.Printf("queue empty, next check in %ds", *interval)
				}
				time.Sleep(time.Duration(*interval) * time.Second)
				continue
			}
			if errors.Is(err, manager.ErrUnauthorized) {
				fmt.Fprintln(os.Stderr, "unauthorized")
				return 2
			}
			fmt.Fprintln(os.Stderr, "next task:", err)
			if *once {
				return 1
			}
			time.Sleep(time.Duration(*interval) * time.Second)
			continue
		}

		log.Printf("task %d: %s %s, downloading %d MB", task.ID, task.Mod.Name, task.Mod.Version, task.Mod.FileSize>>20)

		tmpDir, err := os.MkdirTemp("", "modaudit-")
		if err != nil {
			fmt.Fprintln(os.Stderr, err)
			return 1
		}
		zipPath := filepath.Join(tmpDir, "mod.zip")
		if err := client.DownloadMod(ctx, task.Mod.DownloadURL, zipPath, task.Mod.MD5); err != nil {
			fmt.Fprintln(os.Stderr, "download:", err)
			if *once {
				os.RemoveAll(tmpDir)
				return 1
			}
			os.RemoveAll(tmpDir)
			time.Sleep(time.Duration(*interval) * time.Second)
			continue
		}

		s, err := audit.Run(ctx, zipPath, audit.Options{Slug: "", Limits: audit.Limits(cfg.Limits), Baseline: nil})
		if err != nil {
			fmt.Fprintln(os.Stderr, "audit:", err)
			if *once {
				os.RemoveAll(tmpDir)
				return 1
			}
			os.RemoveAll(tmpDir)
			time.Sleep(time.Duration(*interval) * time.Second)
			continue
		}
		r := report.Build(s)
		log.Printf("task %d: %s, %d findings", task.ID, r.Verdict, len(r.Findings))

		var sigBlob []byte
		if r.Verdict == audit.VerdictSign && (task.TaskType == "sign" || task.TaskType == "audit_and_sign") {
			if cfg.KeyDir != "" && cfg.TargetAlpha != "" {
				if _, ok := trust.ForAlpha(cfg.TargetAlpha); ok {
					if k, err := keys.Select(cfg.KeyDir, cfg.TargetAlpha); err == nil {
						if term, err := deps.openTerminal(); err == nil {
							summary := []string{
								"slug: " + r.Slug,
								"name: " + r.ModJSON.Name + " version: " + r.ModJSON.Version,
								"deps: " + strings.Join(r.ModJSON.Dependencies, ","),
								"zip: " + zipPath,
								"sha256: " + r.ZipSHA256,
								"alpha: " + cfg.TargetAlpha,
								"key: " + k.Path,
							}
							token := r.ZipSHA256
							if len(token) > 12 {
								token = token[:12]
							}
							if okConfirm, err := approval.Confirm(term, summary, token); err == nil && okConfirm {
								passCmd := cfg.VaultCmd
								pw, err := approval.Password(term, passCmd, filepath.Base(k.Path))
								if err == nil {
									keyRaw, err := os.ReadFile(k.Path)
									if err == nil {
										priv, err := minisign.DecryptKey(string(pw), keyRaw)
										if err == nil {
											res, err := signer.Sign(signer.Request{ZipPath: zipPath, WantSHA256: r.ZipSHA256, Alpha: cfg.TargetAlpha, Key: priv})
											if err == nil {
												newBlob, err := blob.Merge(blob.Blob{}, r.ModJSON.Dependencies, res.Signature, zipPath)
												if err == nil {
													if mb, err := blob.Marshal(newBlob); err == nil {
														sigBlob = mb
													}
												}
											}
										}
										for i := range pw {
											pw[i] = 0
										}
									} else {
										for i := range pw {
											pw[i] = 0
										}
									}
								}
							}
							term.Close()
						}
					}
				}
			}
		}

		repData, _ := report.Serialize(r)
		sub := manager.Submission{
			Verdict:       string(r.Verdict),
			Report:        repData,
			SignatureBlob: sigBlob,
		}
		if r.Verdict == audit.VerdictRefuse || r.Verdict == audit.VerdictNeedsHuman {
			sub.CommentDraft = strings.Join(report.Bullets(r, 10), "\n")
		}

		if err := client.SubmitResult(ctx, task.ID, task.ModID, sub); err != nil {
			fmt.Fprintln(os.Stderr, "submit:", err)
			if *once {
				os.RemoveAll(tmpDir)
				return 1
			}
		} else {
			log.Printf("task %d: submitted", task.ID)
		}

		os.RemoveAll(tmpDir)
		if *once {
			return 0
		}
		time.Sleep(time.Duration(*interval) * time.Second)
	}
}
