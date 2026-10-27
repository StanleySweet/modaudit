package manager

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"mime/multipart"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
)

// Review is an audited task waiting for a human decision.
type Review struct {
	TaskID        int64     `json:"task_id"`
	ModID         int64     `json:"mod_id"`
	Name          string    `json:"name"`
	ModIOURL      string    `json:"mod_io_url"`
	Version       string    `json:"version"`
	DownloadURL   string    `json:"download_url"`
	MD5           string    `json:"md5"`
	FileSize      int64     `json:"filesize"`
	Verdict       string    `json:"verdict"`
	ZipSHA256     string    `json:"zip_sha256"`
	ModJSON       ModJSON   `json:"mod_json"`
	Findings      []Finding `json:"findings"`
	CommentDraft  string    `json:"comment_draft"`
	PreviousError string    `json:"previous_error"`
}

type ModJSON struct {
	Name         string   `json:"name"`
	Version      string   `json:"version"`
	Dependencies []string `json:"dependencies"`
}

type Finding struct {
	Code     string `json:"code"`
	Severity string `json:"severity"`
	File     string `json:"file"`
}

// Reviews lists audited tasks that still need a decision.
func (c *Client) Reviews(ctx context.Context) ([]Review, error) {
	resp, err := c.do(ctx, "GET", "/api/v1/reviews", nil, "")
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	var out struct {
		Reviews []Review `json:"reviews"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		return nil, err
	}
	return out.Reviews, nil
}

// Publish asks the manager to set metadataBlob on the reviewed modfile. The manager
// re-hashes the modfile and verifies every signature before writing to mod.io.
func (c *Client) Publish(ctx context.Context, taskID int64, metadataBlob []byte) error {
	body, err := json.Marshal(map[string]string{"metadata_blob": string(metadataBlob)})
	if err != nil {
		return err
	}
	resp, err := c.do(ctx, "POST", fmt.Sprintf("/api/v1/reviews/%d/publish", taskID), bytes.NewReader(body), "application/json")
	if err != nil {
		return err
	}
	return resp.Body.Close()
}

// Comment asks the manager to post the task's comment draft on mod.io.
func (c *Client) Comment(ctx context.Context, taskID int64) error {
	resp, err := c.do(ctx, "POST", fmt.Sprintf("/api/v1/reviews/%d/comment", taskID), nil, "")
	if err != nil {
		return err
	}
	return resp.Body.Close()
}

// Dismiss closes the review without writing to mod.io.
func (c *Client) Dismiss(ctx context.Context, taskID int64) error {
	resp, err := c.do(ctx, "POST", fmt.Sprintf("/api/v1/reviews/%d/dismiss", taskID), nil, "")
	if err != nil {
		return err
	}
	return resp.Body.Close()
}

func (c *Client) do(ctx context.Context, method, path string, body io.Reader, contentType string) (*http.Response, error) {
	req, err := http.NewRequestWithContext(ctx, method, c.baseURL+path, body)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Authorization", "Bearer "+c.apiKey)
	req.Header.Set("Accept", "application/json")
	if contentType != "" {
		req.Header.Set("Content-Type", contentType)
	}
	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, err
	}
	if resp.StatusCode == http.StatusUnauthorized {
		resp.Body.Close()
		return nil, ErrUnauthorized
	}
	if resp.StatusCode >= 300 {
		b, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
		resp.Body.Close()
		return nil, fmt.Errorf("%s %s: status %d: %s", method, path, resp.StatusCode, b)
	}
	return resp, nil
}

// Repackaged describes a rebuilt zip for upload.
type Repackaged struct {
	ZipPath      string
	SHA256       string
	OldVersion   string
	NewVersion   string
	Added        int
	MetadataBlob []byte
}

// Repackage streams the rebuilt zip to the manager, which re-hashes it, verifies
// the signatures and uploads it to mod.io as a new modfile.
func (c *Client) Repackage(ctx context.Context, taskID int64, r Repackaged) error {
	pr, pw := io.Pipe()
	mw := multipart.NewWriter(pw)
	go func() {
		err := func() error {
			for k, v := range map[string]string{
				"metadata_blob":  string(r.MetadataBlob),
				"old_version":    r.OldVersion,
				"new_version":    r.NewVersion,
				"rebuilt_sha256": r.SHA256,
				"added":          strconv.Itoa(r.Added),
			} {
				if err := mw.WriteField(k, v); err != nil {
					return err
				}
			}
			f, err := os.Open(r.ZipPath)
			if err != nil {
				return err
			}
			defer f.Close()
			part, err := mw.CreateFormFile("filedata", filepath.Base(r.ZipPath))
			if err != nil {
				return err
			}
			if _, err := io.Copy(part, f); err != nil {
				return err
			}
			return mw.Close()
		}()
		pw.CloseWithError(err)
	}()
	resp, err := c.do(ctx, "POST", fmt.Sprintf("/api/v1/reviews/%d/repackage", taskID), pr, mw.FormDataContentType())
	if err != nil {
		pr.CloseWithError(err)
		return err
	}
	return resp.Body.Close()
}
