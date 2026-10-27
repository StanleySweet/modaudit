package config

import (
	"errors"
	"io/fs"

	"github.com/BurntSushi/toml"
)

// Limits are the hard caps applied while scanning an archive.
type Limits struct {
	MaxEntries      int     `toml:"max_entries"`
	MaxUncompressed int64   `toml:"max_uncompressed"`
	MaxRatio        float64 `toml:"max_ratio"`
	MaxFileSize     int64   `toml:"max_file_size"`
	MaxScriptBytes  int64   `toml:"max_script_bytes"`
	MaxBundleBytes  int     `toml:"max_bundle_bytes"`
	MaxBundleFiles  int     `toml:"max_bundle_files"`
}

// Config is the on-disk config.toml. Secrets are referenced, never inlined.
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

// Default returns the built-in configuration, including every hard cap.
func Default() Config {
	return Config{
		Limits: Limits{
			MaxEntries:      100000,
			MaxUncompressed: 2 << 30,
			MaxRatio:        100,
			MaxFileSize:     64 << 20,
			MaxScriptBytes:  2 << 20,
			MaxBundleBytes:  200 * 1024,
			MaxBundleFiles:  50,
		},
	}
}

// Load reads path over the defaults. A missing file yields the defaults.
func Load(path string) (Config, error) {
	cfg := Default()
	if path == "" {
		return cfg, nil
	}
	if _, err := toml.DecodeFile(path, &cfg); err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			return cfg, nil
		}
		return cfg, err
	}
	return cfg, nil
}
