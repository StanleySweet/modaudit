package signer

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"time"

	"aead.dev/minisign"

	"github.com/stan/modaudit/internal/trust"
)

var (
	ErrHashMismatch = errors.New("hash mismatch")
	ErrWrongKey     = errors.New("wrong key for alpha")
)

// Request for signing.
type Request struct {
	ZipPath    string
	WantSHA256 string
	Alpha      string
	Key        minisign.PrivateKey
}

// Result of signing.
type Result struct {
	Signature []byte
	SHA256    string
	KeyID     uint64
}

// Sign signs the zip bytes.
func Sign(req Request) (Result, error) {
	// check key matches trust store for alpha
	pk, ok := trust.ForAlpha(req.Alpha)
	if !ok {
		return Result{}, ErrWrongKey
	}
	if req.Key.Public().(minisign.PublicKey).ID() != pk.ID() {
		return Result{}, ErrWrongKey
	}

	f, err := os.Open(req.ZipPath)
	if err != nil {
		return Result{}, err
	}
	defer f.Close()

	h := sha256.New()
	tr := io.TeeReader(f, h)
	r := minisign.NewReader(tr)
	if _, err := io.Copy(io.Discard, r); err != nil {
		return Result{}, err
	}
	sum := hex.EncodeToString(h.Sum(nil))
	if !strings.EqualFold(sum, req.WantSHA256) {
		return Result{}, ErrHashMismatch
	}

	// trusted comment: timestamp:<unix>\tfile:<base name>\thashed
	ts := time.Now().Unix()
	trusted := fmt.Sprintf("timestamp:%d\tfile:%s\thashed", ts, filepath.Base(req.ZipPath))
	untrusted := "signature from minisign secret key"
	sig := r.SignWithComments(req.Key, trusted, untrusted)

	// re-open and verify
	f2, err := os.Open(req.ZipPath)
	if err != nil {
		return Result{}, err
	}
	defer f2.Close()
	if !minisign.NewReader(f2).Verify(pk, sig) {
		return Result{}, errors.New("verification failed")
	}

	return Result{Signature: sig, SHA256: sum, KeyID: req.Key.ID()}, nil
}
