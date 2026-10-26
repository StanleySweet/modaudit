package blob

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"strings"

	"aead.dev/minisign"

	"github.com/stan/modaudit/internal/trust"
)

// Blob is the metadata blob.
type Blob struct {
	Dependencies []string `json:"dependencies"`
	Minisigs     []string `json:"minisigs"`
}

// Entry represents a validated entry.
type Entry struct {
	KeyID  uint64
	Alphas []string
}

// Parse parses blob JSON.
func Parse(b []byte) (Blob, error) {
	var blob Blob
	if err := json.Unmarshal(b, &blob); err != nil {
		return Blob{}, err
	}
	if blob.Minisigs == nil {
		blob.Minisigs = []string{}
	}
	if blob.Dependencies == nil {
		blob.Dependencies = []string{}
	}
	return blob, nil
}

// Validate validates all entries against zip bytes.
func Validate(b Blob, zipPath string) ([]Entry, error) {
	zip, err := os.ReadFile(zipPath)
	if err != nil {
		return nil, err
	}
	var entries []Entry
	seen := map[uint64]bool{}
	for _, s := range b.Minisigs {
		e, err := validateEntry(s, zip)
		if err != nil {
			return nil, err
		}
		if seen[e.KeyID] {
			return nil, errors.New("duplicate key")
		}
		seen[e.KeyID] = true
		entries = append(entries, e)
	}
	return entries, nil
}

func validateEntry(s string, zip []byte) (Entry, error) {
	// normalize
	s = strings.ReplaceAll(s, "\r", "")
	lines := strings.Split(s, "\n")
	if len(lines) < 4 {
		return Entry{}, errors.New("bad entry")
	}
	if !strings.HasPrefix(lines[0], "untrusted comment: ") {
		return Entry{}, errors.New("bad entry")
	}
	if !strings.HasPrefix(lines[1], "trusted comment: ") {
		return Entry{}, errors.New("bad entry")
	}
	// line 2 is signature base64 (74 chars typical for prehashed)
	if len(lines[2]) != 74 {
		return Entry{}, errors.New("bad entry")
	}
	if lines[3] != "ED" {
		return Entry{}, errors.New("bad entry")
	}
	var sig minisign.Signature
	if err := sig.UnmarshalText([]byte(lines[0] + "\n" + lines[1] + "\n" + lines[2] + "\n" + lines[3])); err != nil {
		// try without trailing empty
		if err := sig.UnmarshalText([]byte(s)); err != nil {
			return Entry{}, err
		}
	}
	pk := minisign.PublicKey{}
	if err := pk.UnmarshalText([]byte("untrusted comment: minisign public key: " + fmt.Sprintf("%016X", sig.KeyID) + "\n" + "RW" + strings.Repeat("A", 56))); err != nil {
		// not needed
	}
	// find by key id
	k, ok := trust.ByID(sig.KeyID)
	if !ok {
		return Entry{}, errors.New("unknown key")
	}
	if !minisign.Verify(k.Public, zip, []byte(s)) {
		return Entry{}, errors.New("bad signature")
	}
	return Entry{KeyID: sig.KeyID, Alphas: k.Alphas}, nil
}

// Merge merges signature into blob.
func Merge(old Blob, deps []string, sig []byte, zipPath string) (Blob, error) {
	// normalize new sig
	s := string(sig)
	s = strings.ReplaceAll(s, "\r", "")
	s = strings.TrimRight(s, "\n")
	// validate new sig
	if _, err := validateEntry(s, nil); err != nil {
		// try with actual zip
		zip, err2 := os.ReadFile(zipPath)
		if err2 != nil {
			return Blob{}, err2
		}
		if _, err := validateEntry(s, zip); err != nil {
			return Blob{}, err
		}
	}
	// get key id
	var sigobj minisign.Signature
	_ = sigobj.UnmarshalText([]byte(s))
	// build new blob
	out := Blob{Dependencies: append([]string(nil), deps...), Minisigs: []string{}}
	// keep existing entries that verify
	zip, _ := os.ReadFile(zipPath)
	for _, es := range old.Minisigs {
		es2 := strings.ReplaceAll(es, "\r", "")
		es2 = strings.TrimRight(es2, "\n")
		e, err := validateEntry(es2, zip)
		if err != nil {
			return Blob{}, err
		}
		if e.KeyID == sigobj.KeyID {
			continue // replaced
		}
		out.Minisigs = append(out.Minisigs, es2)
	}
	out.Minisigs = append(out.Minisigs, s)
	return out, nil
}

// Marshal marshals blob.
func Marshal(b Blob) ([]byte, error) {
	return json.MarshalIndent(b, "", "  ")
}
