package manager

import (
	"bytes"
	"context"
	"crypto/md5"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"mime/multipart"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"
)

type Client struct {
	baseURL    string
	apiKey     string
	httpClient *http.Client
}

func NewClient(baseURL, apiKey string) *Client {
	return &Client{
		baseURL: strings.TrimRight(baseURL, "/"),
		apiKey:  apiKey,
		httpClient: &http.Client{
			Timeout: 30 * time.Minute, // allow large downloads/uploads
		},
	}
}

func (c *Client) NextTask(ctx context.Context) (*Task, error) {
	req, err := http.NewRequestWithContext(ctx, "GET", c.baseURL+"/api/v1/queue/next", nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Authorization", "Bearer "+c.apiKey)
	req.Header.Set("Accept", "application/json")

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusNotFound {
		return nil, ErrNoTask
	}
	if resp.StatusCode == http.StatusUnauthorized {
		return nil, ErrUnauthorized
	}
	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("unexpected status %d: %s", resp.StatusCode, string(body))
	}

	var raw map[string]any
	if err := json.NewDecoder(resp.Body).Decode(&raw); err != nil {
		return nil, err
	}

	task := &Task{}
	if t, ok := raw["task"].(map[string]any); ok {
		if v, ok := t["id"].(float64); ok {
			task.ID = int64(v)
		}
		if v, ok := t["mod_id"].(float64); ok {
			task.ModID = int64(v)
		}
		if v, ok := t["mod_version_id"].(float64); ok {
			task.ModVersionID = int64(v)
		}
		if v, ok := t["task_type"].(string); ok {
			task.TaskType = v
		}
		if v, ok := t["payload"].(map[string]any); ok {
			task.Payload = v
		}
	}
	if m, ok := raw["mod"].(map[string]any); ok {
		if v, ok := m["name"].(string); ok {
			task.Mod.Name = v
		}
		if v, ok := m["version"].(string); ok {
			task.Mod.Version = v
		}
		if v, ok := m["mod_io_url"].(string); ok {
			task.Mod.ModIOURL = v
		}
		if v, ok := m["download_url"].(string); ok {
			task.Mod.DownloadURL = v
		}
		if v, ok := m["md5"].(string); ok {
			task.Mod.MD5 = v
		}
		if v, ok := m["filesize"].(float64); ok {
			task.Mod.FileSize = int64(v)
		}
	}

	return task, nil
}

func (c *Client) DownloadMod(ctx context.Context, url, destPath, expectedMD5 string) error {
	req, err := http.NewRequestWithContext(ctx, "GET", url, nil)
	if err != nil {
		return err
	}
	resp, err := c.httpClient.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("download failed with status %d", resp.StatusCode)
	}

	out, err := os.Create(destPath)
	if err != nil {
		return err
	}
	defer out.Close()

	h := md5.New()
	if _, err := io.Copy(io.MultiWriter(out, h), resp.Body); err != nil {
		return err
	}

	if expectedMD5 != "" {
		got := hex.EncodeToString(h.Sum(nil))
		if !strings.EqualFold(got, expectedMD5) {
			return fmt.Errorf("checksum mismatch: got %s expected %s", got, expectedMD5)
		}
	}
	return nil
}

func (c *Client) SubmitResult(ctx context.Context, taskID, modID int64, sub Submission) error {
	body := &bytes.Buffer{}
	writer := multipart.NewWriter(body)

	_ = writer.WriteField("task_id", fmt.Sprintf("%d", taskID))
	_ = writer.WriteField("verdict", sub.Verdict)
	if len(sub.Report) > 0 {
		_ = writer.WriteField("report", string(sub.Report))
	}
	if len(sub.SignatureBlob) > 0 {
		_ = writer.WriteField("signature_blob", string(sub.SignatureBlob))
	}
	if sub.CommentDraft != "" {
		_ = writer.WriteField("comment_draft", sub.CommentDraft)
	}

	if sub.RepackagedZip != "" {
		f, err := os.Open(sub.RepackagedZip)
		if err != nil {
			return err
		}
		part, err := writer.CreateFormFile("repackaged_zip", filepath.Base(sub.RepackagedZip))
		if err != nil {
			f.Close()
			return err
		}
		if _, err := io.Copy(part, f); err != nil {
			f.Close()
			return err
		}
		f.Close()
	}

	if err := writer.Close(); err != nil {
		return err
	}

	url := fmt.Sprintf("%s/api/v1/mods/%d/submissions", c.baseURL, modID)
	req, err := http.NewRequestWithContext(ctx, "POST", url, body)
	if err != nil {
		return err
	}
	req.Header.Set("Authorization", "Bearer "+c.apiKey)
	req.Header.Set("Content-Type", writer.FormDataContentType())

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		respBody, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("submit failed with status %d: %s", resp.StatusCode, string(respBody))
	}
	return nil
}

var (
	ErrNoTask       = errors.New("no task")
	ErrUnauthorized = errors.New("unauthorized")
)
