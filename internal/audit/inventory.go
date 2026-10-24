package audit

import (
	"archive/zip"
	"bufio"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path"
	"strings"

	"github.com/stan/modaudit/internal/config"
)

const maxModJSON = 1 << 20

func (l Limits) normalized() Limits {
	d := config.Default().Limits
	if l.MaxEntries == 0 {
		l.MaxEntries = d.MaxEntries
	}
	if l.MaxUncompressed == 0 {
		l.MaxUncompressed = d.MaxUncompressed
	}
	if l.MaxRatio == 0 {
		l.MaxRatio = d.MaxRatio
	}
	if l.MaxFileSize == 0 {
		l.MaxFileSize = d.MaxFileSize
	}
	if l.MaxScriptBytes == 0 {
		l.MaxScriptBytes = d.MaxScriptBytes
	}
	if l.MaxBundleBytes == 0 {
		l.MaxBundleBytes = d.MaxBundleBytes
	}
	if l.MaxBundleFiles == 0 {
		l.MaxBundleFiles = d.MaxBundleFiles
	}
	return l
}

// Inventory streams the archive, hashes it and every entry, and applies the
// hard caps. Rule violations are left to the rule functions.
func Inventory(ctx context.Context, zipPath string, lim Limits) (*Scan, error) {
	lim = lim.normalized()
	f, err := os.Open(zipPath)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	h := sha256.New()
	zipSize, err := io.Copy(h, f)
	if err != nil {
		return nil, err
	}
	if _, err := f.Seek(0, io.SeekStart); err != nil {
		return nil, err
	}

	zr, err := zip.NewReader(f, zipSize)
	if err != nil {
		return nil, fmt.Errorf("not a zip: %w", err)
	}

	s := &Scan{Path: zipPath, ZipSHA256: hex.EncodeToString(h.Sum(nil))}
	var compressedTotal int64

	for _, zf := range zr.File {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		if len(s.Entries) >= lim.MaxEntries {
			s.Aborted, s.AbortCode = true, "ZIP_TOO_MANY_ENTRIES"
			break
		}

		e := Entry{
			Name:           zf.Name,
			Size:           int64(zf.UncompressedSize64),
			CompressedSize: int64(zf.CompressedSize64),
			Mode:           zf.Mode(),
			Flags:          zf.Flags,
		}
		s.TotalUncompressed += e.Size
		compressedTotal += e.CompressedSize

		if s.TotalUncompressed > lim.MaxUncompressed {
			s.Aborted, s.AbortCode = true, "ZIP_TOO_LARGE"
			break
		}
		if compressedTotal > 0 && float64(s.TotalUncompressed)/float64(compressedTotal) > lim.MaxRatio*10 {
			s.Aborted, s.AbortCode = true, "ZIP_BOMB_RATIO"
			break
		}

		rc, err := zf.Open()
		if err != nil {
			s.AddFinding("ZIP_UNREADABLE_ENTRY", SeverityBlocker, zf.Name, err.Error())
			s.Entries = append(s.Entries, e)
			continue
		}
		br := bufio.NewReader(io.LimitReader(rc, lim.MaxFileSize+1))
		magic, _ := br.Peek(8)
		eh := sha256.New()
		n, _ := io.Copy(eh, br)
		rc.Close()
		if n > lim.MaxFileSize {
			e.Truncated = true
		}
		e.SHA256 = hex.EncodeToString(eh.Sum(nil))
		e.Kind = classify(e.Name, magic)

		if e.Mode&fs.ModeSymlink != 0 {
			body, _ := readLimited(zipPath, zf.Name, 4096)
			e.Link = string(body)
		}
		if e.Name == "mod.json" {
			body, _ := readLimited(zipPath, zf.Name, maxModJSON)
			s.ModJSONRaw = body
		}

		s.Entries = append(s.Entries, e)
	}
	return s, nil
}

func readLimited(zipPath, name string, max int64) ([]byte, error) {
	zr, err := zip.OpenReader(zipPath)
	if err != nil {
		return nil, err
	}
	defer zr.Close()
	for _, zf := range zr.File {
		if zf.Name != name {
			continue
		}
		rc, err := zf.Open()
		if err != nil {
			return nil, err
		}
		defer rc.Close()
		return io.ReadAll(io.LimitReader(rc, max))
	}
	return nil, fs.ErrNotExist
}

var kindsByExt = map[string]Kind{
	".js": KindJS, ".mjs": KindJS,
	".xml": KindXML, ".xmb": KindBinary,
	".json":  KindJSON,
	".png":   KindImage, ".jpg": KindImage, ".jpeg": KindImage,
	".dds": KindImage, ".tga": KindImage, ".bmp": KindImage,
	".ktx": KindImage, ".webp": KindImage,
	".zip": KindArchive, ".pyromod": KindArchive, ".7z": KindArchive, ".rar": KindArchive,
	".exe": KindBinary, ".dll": KindBinary, ".so": KindBinary, ".dylib": KindBinary,
	".pmd": KindBinary, ".psa": KindBinary, ".node": KindBinary,
}

func classify(name string, magic []byte) Kind {
	if k, ok := kindsByExt[strings.ToLower(path.Ext(name))]; ok {
		return k
	}
	m := string(magic)
	switch {
	case strings.HasPrefix(m, "DDS "):
		return KindImage
	case strings.HasPrefix(m, "XMBF"), strings.HasPrefix(m, "PSMD"):
		return KindBinary
	case strings.HasPrefix(m, "PK\x03\x04"):
		return KindArchive
	case strings.HasPrefix(m, "MZ"), strings.HasPrefix(m, "\x7fELF"),
		strings.HasPrefix(m, "\xfe\xed\xfa"), strings.HasPrefix(m, "\xca\xfe\xba\xbe"):
		return KindBinary
	}
	return KindOther
}
