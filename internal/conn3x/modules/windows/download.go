// Copyright (c) The Conn3x Authors
// SPDX-License-Identifier: MPL-2.0

package windows

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/opentofu/opentofu/internal/conn3x/modules/windows/ps"
)

// Download is a file fetched from URL to Dest, which must have SHA256.
type Download struct {
	URL       string
	Dest      string
	SHA256    string
	AllowHTTP bool // url may be, or redirect to, plain http
	MaxSizeMB int  // largest download; 0 is DefaultMaxSizeMB
}

// Validate checks a download before anything reaches a host.
func (d Download) Validate() error {
	if err := validDownloadURL(d.URL, d.AllowHTTP); err != nil {
		return err
	}
	if _, err := CleanLocalPath("dest", d.Dest); err != nil {
		return err
	}
	if d.MaxSizeMB < 0 {
		return errors.New("max_size_mb must be positive")
	}
	if !sha256Hex.MatchString(strings.ToLower(d.SHA256)) {
		return errors.New("sha256 must be the file's SHA-256, as 64 hex characters")
	}
	return nil
}

// DownloadInSync reports whether Dest is a file whose SHA-256 is SHA256. A
// link at Dest, or a folder on the way that's one, isn't.
func DownloadInSync(ctx context.Context, r ps.Runner, d Download) (bool, error) {
	st, err := ReadPath(ctx, r, d.Dest, nil, true)
	if err != nil {
		return false, err
	}
	if st.Kind == "directory" {
		return false, fmt.Errorf("dest %s is a folder", d.Dest)
	}
	return st.Kind == "file" && st.LinkOnWay == "" && strings.EqualFold(st.SHA256, d.SHA256), nil
}

// ApplyDownload fetches URL into a temp file beside Dest, checks its hash,
// and only then renames it over Dest, so Dest is never a partial or
// mismatched download.
func ApplyDownload(ctx context.Context, r ps.Runner, d Download, timeout time.Duration) error {
	maxMB := d.MaxSizeMB
	if maxMB == 0 {
		maxMB = DefaultMaxSizeMB
	}
	res, err := ps.Apply(ctx, r, script("apply_download.ps1"), map[string]any{
		"path": d.Dest, "url": d.URL, "sha256": strings.ToLower(d.SHA256), "allow_http": d.AllowHTTP, "max_bytes": int64(maxMB) << 20,
	}, timeout)
	if err != nil {
		return err
	}
	var a struct {
		SHA256 string `json:"sha256"`
	}
	if err := json.Unmarshal(res.Value, &a); err != nil {
		return fmt.Errorf("reading the result of downloading %s: %w", d.Dest, err)
	}
	if !strings.EqualFold(a.SHA256, d.SHA256) {
		return fmt.Errorf("%s was written with SHA-256 %s, not %s", d.Dest, a.SHA256, d.SHA256)
	}
	return nil
}
