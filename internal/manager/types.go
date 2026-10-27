package manager

type Task struct {
	ID           int64
	ModID        int64
	ModVersionID int64
	TaskType     string // "audit", "sign", "audit_and_sign"
	Payload      map[string]any
	Mod          ModInfo
}

type ModInfo struct {
	Name        string
	Version     string
	ModIOURL    string
	DownloadURL string
	MD5         string // mod.io filehash.md5, transfer check only
	FileSize    int64
}

type Submission struct {
	Verdict       string
	Report        []byte // JSON report.Report
	SignatureBlob []byte // JSON blob.Blob (optional)
	CommentDraft  string // optional
	RepackagedZip string // path to zip file (optional)
}
