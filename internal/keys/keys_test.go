package keys

import (
	"errors"
	"os"
	"path/filepath"
	"testing"
)

func TestSelectExactAlphaOnly(t *testing.T) {
	dir := t.TempDir()
	for _, n := range []string{"minisign-0.0.27.pem", "minisign-releases.pem", "Readme.MD"} {
		os.WriteFile(filepath.Join(dir, n), []byte("x"), 0o600)
	}
	if _, err := Select(dir, "0.28.0"); !errors.Is(err, ErrNoKey) {
		t.Fatalf("err = %v", err)
	}
	k, err := Select(dir, "0.0.27")
	if err != nil || k.Alpha != "0.0.27" {
		t.Fatalf("%+v %v", k, err)
	}
	if _, err := Select(dir, "releases"); !errors.Is(err, ErrNoKey) {
		t.Fatal("release key selectable")
	}
}
