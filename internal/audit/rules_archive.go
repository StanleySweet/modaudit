package audit

import (
	"io/fs"
	"path"
	"strings"
	"unicode/utf8"
)

// NormalizeName canonicalises an archive entry name and reports whether the
// original bytes were valid UTF-8.
func NormalizeName(name string) (string, bool) {
	ok := utf8.ValidString(name)
	n := strings.ReplaceAll(name, `\`, "/")
	n = strings.TrimPrefix(n, "./")
	n = path.Clean(n)
	if n == "." {
		n = ""
	}
	return n, ok
}

func rulesArchive(s *Scan) {
	if len(s.Entries) == 0 {
		s.AddFinding("ZIP_EMPTY", SeverityBlocker, "", "archive has no entries")
		return
	}

	seen := make(map[string]string, len(s.Entries))
	var compressedTotal int64

	for _, e := range s.Entries {
		norm, utf8OK := NormalizeName(e.Name)
		if !utf8OK {
			s.AddFinding("ZIP_NAME_ENCODING", SeverityBlocker, e.Name, "entry name is not valid UTF-8")
		}
		if norm == ".." || strings.HasPrefix(norm, "../") {
			s.AddFinding("ZIP_PATH_TRAVERSAL", SeverityBlocker, e.Name, "entry escapes the archive root")
		}
		if strings.HasPrefix(norm, "/") || isDrivePath(norm) {
			s.AddFinding("ZIP_ABSOLUTE_PATH", SeverityBlocker, e.Name, "entry uses an absolute path")
		}
		if e.Mode&fs.ModeSymlink != 0 {
			s.AddFinding("ZIP_SYMLINK", SeverityBlocker, e.Name, "entry is a symlink")
		}
		if e.Flags&0x1 != 0 {
			s.AddFinding("ZIP_ENCRYPTED", SeverityBlocker, e.Name, "entry is encrypted")
		}
		key := strings.ToLower(norm)
		if prev, ok := seen[key]; ok {
			s.AddFinding("ZIP_DUPLICATE_NAME", SeverityBlocker, e.Name, "duplicate of "+prev)
		} else {
			seen[key] = e.Name
		}
		compressedTotal += e.CompressedSize
	}

	ratio := s.Limits.MaxRatio
	if ratio == 0 {
		ratio = 100
	}
	if compressedTotal > 0 {
		if r := float64(s.TotalUncompressed) / float64(compressedTotal); r > ratio {
			s.AddFinding("ZIP_BOMB_RATIO", SeverityBlocker, "",
				"compression ratio exceeds limit")
		}
	}
	for _, e := range s.Entries {
		if e.Size > s.Limits.MaxFileSize {
			s.AddFinding("ZIP_ENTRY_OVERSIZED", SeverityWarn, e.Name, "entry exceeds the per-file cap")
		}
	}
}

func isDrivePath(n string) bool {
	return len(n) >= 2 && n[1] == ':' &&
		((n[0] >= 'a' && n[0] <= 'z') || (n[0] >= 'A' && n[0] <= 'Z'))
}
