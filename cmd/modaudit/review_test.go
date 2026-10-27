package main

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"

	"github.com/stan/modaudit/internal/approval"
)

type scriptedTerm struct {
	answers []string
	out     []string
}

func (t *scriptedTerm) ReadPassword(string) ([]byte, error) { return []byte("x"), nil }
func (t *scriptedTerm) ReadLine(string) (string, error) {
	if len(t.answers) == 0 {
		return "", nil
	}
	a := t.answers[0]
	t.answers = t.answers[1:]
	return a, nil
}
func (t *scriptedTerm) Println(s string) { t.out = append(t.out, s) }
func (t *scriptedTerm) Close() error     { return nil }

func TestReviewCommentDismissSkip(t *testing.T) {
	var mu sync.Mutex
	var calls []string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer k" {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		mu.Lock()
		calls = append(calls, r.Method+" "+r.URL.Path)
		mu.Unlock()
		if r.URL.Path == "/api/v1/reviews" {
			json.NewEncoder(w).Encode(map[string]any{"reviews": []map[string]any{
				{"task_id": 1, "name": "a", "verdict": "REFUSE", "comment_draft": "- no mod.json", "findings": []map[string]string{{"code": "LAYOUT_NO_MODJSON"}}},
				{"task_id": 2, "name": "b", "verdict": "NEEDS_HUMAN"},
				{"task_id": 3, "name": "c", "verdict": "REFUSE", "comment_draft": "- x"},
				{"task_id": 4, "name": "d", "verdict": "SIGN"},
			}})
			return
		}
		w.Write([]byte(`{}`))
	}))
	defer srv.Close()

	dir := t.TempDir()
	keyFile := filepath.Join(dir, "key")
	os.WriteFile(keyFile, []byte("k\n"), 0o600)
	cfgPath := filepath.Join(dir, "config.toml")
	os.WriteFile(cfgPath, []byte("manager_url = \""+srv.URL+"\"\napi_key_file = \""+keyFile+"\"\n"), 0o600)

	// task 1: comment, task 2: dismiss, task 3: default skip, task 4: SIGN without key_dir
	term := &scriptedTerm{answers: []string{"c", "d", ""}}
	code := runReview([]string{"--config", cfgPath}, reviewDeps{openTerminal: func() (approval.Terminal, error) { return term, nil }})
	if code != 0 {
		t.Fatalf("exit %d", code)
	}
	want := []string{"GET /api/v1/reviews", "POST /api/v1/reviews/1/comment", "POST /api/v1/reviews/2/dismiss"}
	if strings.Join(calls, "|") != strings.Join(want, "|") {
		t.Fatalf("calls %v, want %v", calls, want)
	}
	out := strings.Join(term.out, "\n")
	if !strings.Contains(out, "LAYOUT_NO_MODJSON") || !strings.Contains(out, "set key_dir and target_alpha") {
		t.Fatalf("output missing findings or sign config error:\n%s", out)
	}
}
