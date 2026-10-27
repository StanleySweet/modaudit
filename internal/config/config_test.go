package config

import (
	"os"
	"path/filepath"
	"testing"
)

func TestLoadReadsAlphaAndLimits(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "config.toml")
	if err := os.WriteFile(path, []byte("target_alpha = \"0.28.0\"\n[limits]\nmax_entries = 1234\n"), 0o600); err != nil {
		t.Fatal(err)
	}

	cfg, err := Load(path)
	if err != nil {
		t.Fatal(err)
	}
	if cfg.TargetAlpha != "0.28.0" {
		t.Fatalf("alpha = %q", cfg.TargetAlpha)
	}
	if cfg.Limits.MaxEntries != 1234 {
		t.Fatalf("entries = %d", cfg.Limits.MaxEntries)
	}
	if cfg.Limits.MaxBundleBytes != 200*1024 {
		t.Fatalf("default bundle cap lost: %d", cfg.Limits.MaxBundleBytes)
	}
}

func TestLoadMissingFileReturnsDefaults(t *testing.T) {
	cfg, err := Load(filepath.Join(t.TempDir(), "nope.toml"))
	if err != nil {
		t.Fatal(err)
	}
	if cfg.Limits.MaxEntries != 100000 {
		t.Fatalf("entries = %d", cfg.Limits.MaxEntries)
	}
}
