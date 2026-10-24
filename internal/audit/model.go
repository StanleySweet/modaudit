package audit

import (
	"io/fs"

	"github.com/stan/modaudit/internal/config"
)

// Limits are the hard caps applied while scanning.
type Limits config.Limits

// Kind is the coarse type of a zip entry.
type Kind string

const (
	KindJS      Kind = "js"
	KindXML     Kind = "xml"
	KindJSON    Kind = "json"
	KindImage   Kind = "image"
	KindBinary  Kind = "binary"
	KindArchive Kind = "archive"
	KindOther   Kind = "other"
)

// Entry is one file in the archive. Content is never retained.
type Entry struct {
	Name           string      `json:"name"`
	Size           int64       `json:"size"`
	CompressedSize int64       `json:"compressed_size"`
	Mode           fs.FileMode `json:"mode"`
	SHA256         string      `json:"sha256"`
	Kind           Kind        `json:"kind"`
	Link           string      `json:"link,omitempty"`
	Flags          uint16      `json:"flags"`
	Truncated      bool        `json:"truncated,omitempty"`
}

// Severity grades a finding. Only SeverityBlocker forces REFUSE.
type Severity string

const (
	SeverityBlocker Severity = "blocker"
	SeverityWarn    Severity = "warn"
	SeverityInfo    Severity = "info"
)

// Finding is one rule violation.
type Finding struct {
	Code     string   `json:"code"`
	Severity Severity `json:"severity"`
	File     string   `json:"file,omitempty"`
	Detail   string   `json:"detail,omitempty"`
}

// ModInfo is the parsed mod.json.
type ModInfo struct {
	Name          string   `json:"name,omitempty"`
	Version       string   `json:"version,omitempty"`
	Label         string   `json:"label,omitempty"`
	Dependencies  []string `json:"dependencies,omitempty"`
	IgnoreCompat  bool     `json:"ignore_compat,omitempty"`
	UnknownFields []string `json:"unknown_fields,omitempty"`
}

// Verdict is the audit outcome.
type Verdict string

const (
	VerdictSign       Verdict = "SIGN"
	VerdictRepackage  Verdict = "REPACKAGE"
	VerdictRefuse     Verdict = "REFUSE"
	VerdictNeedsHuman Verdict = "NEEDS_HUMAN"
)

// Scan is the result of reading and auditing one archive.
type Scan struct {
	Path              string
	Slug              string
	ZipSHA256         string
	Entries           []Entry
	TotalUncompressed int64
	ModJSONRaw        []byte
	ModInfo           ModInfo
	Findings          []Finding
	Verdict           Verdict
	Limits            Limits
	Aborted           bool
	AbortCode         string
}

// AddFinding appends a finding.
func (s *Scan) AddFinding(code string, sev Severity, file, detail string) {
	s.Findings = append(s.Findings, Finding{Code: code, Severity: sev, File: file, Detail: detail})
}
