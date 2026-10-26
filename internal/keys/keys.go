package keys

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
)

var ErrNoKey = errors.New("no key")

var alphaRe = regexp.MustCompile(`^\d+(\.\d+)+$`)

// Key is a discovered key for an alpha.
type Key struct {
	Alpha string
	Path  string
}

// Discover returns keys sorted by name for display only.
func Discover(dir string) ([]Key, error) {
	if dir == "" {
		return nil, fmt.Errorf("key_dir required")
	}
	entries, err := os.ReadDir(dir)
	if err != nil {
		return nil, err
	}
	var keys []Key
	for _, e := range entries {
		if e.IsDir() {
			continue
		}
		name := e.Name()
		if !strings.HasPrefix(name, "minisign-") || !strings.HasSuffix(name, ".pem") {
			continue
		}
		if name == "minisign-releases.pem" {
			continue
		}
		alpha := strings.TrimSuffix(strings.TrimPrefix(name, "minisign-"), ".pem")
		if !alphaRe.MatchString(alpha) {
			continue
		}
		keys = append(keys, Key{Alpha: alpha, Path: filepath.Join(dir, name)})
	}
	sort.Slice(keys, func(i, j int) bool { return keys[i].Path < keys[j].Path })
	return keys, nil
}

// Select returns the key for the exact alpha.
func Select(dir, alpha string) (Key, error) {
	if alpha == "" {
		return Key{}, fmt.Errorf("target_alpha required")
	}
	if dir == "" {
		return Key{}, fmt.Errorf("key_dir required")
	}
	if alpha == "releases" {
		return Key{}, ErrNoKey
	}
	if !alphaRe.MatchString(alpha) {
		return Key{}, ErrNoKey
	}
	path := filepath.Join(dir, "minisign-"+alpha+".pem")
	if _, err := os.Stat(path); err != nil {
		if os.IsNotExist(err) {
			return Key{}, ErrNoKey
		}
		return Key{}, err
	}
	return Key{Alpha: alpha, Path: path}, nil
}
