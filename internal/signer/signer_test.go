package signer

import (
	"crypto/rand"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"aead.dev/minisign"
)

func TestSignVerifiesAndRefusesMismatch(t *testing.T) {
	_, priv, err := minisign.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	p := filepath.Join(t.TempDir(), "m.zip")
	os.WriteFile(p, []byte("zip bytes"), 0o600)
	if _, err := Sign(Request{ZipPath: p, WantSHA256: strings.Repeat("0", 64), Alpha: "0.28.0", Key: priv}); !errors.Is(err, ErrHashMismatch) && !errors.Is(err, ErrWrongKey) {
		t.Fatalf("err = %v", err)
	}
}
