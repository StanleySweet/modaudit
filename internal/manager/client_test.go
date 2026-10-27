package manager

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestClient_NextTask(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer test-key" {
			w.WriteHeader(401)
			return
		}
		w.WriteHeader(200)
		json.NewEncoder(w).Encode(map[string]any{
			"task": map[string]any{"id": 1, "mod_id": 10, "mod_version_id": 20, "task_type": "audit_and_sign"},
			"mod":  map[string]any{"name": "test", "version": "1.0", "download_url": "http://example.com/mod.zip", "md5": "abc123", "filesize": 100},
		})
	}))
	defer ts.Close()

	c := NewClient(ts.URL, "test-key")
	task, err := c.NextTask(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if task.ID != 1 || task.ModID != 10 {
		t.Fatalf("bad task: %+v", task)
	}
}
