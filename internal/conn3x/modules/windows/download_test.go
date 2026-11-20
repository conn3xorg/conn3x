// Copyright (c) The Conn3x Authors
// SPDX-License-Identifier: MPL-2.0

package windows

import (
	"context"
	"strings"
	"testing"
	"time"
)

func TestDownload(t *testing.T) {
	ctx := context.Background()
	const sum = "ec6af1ea0367d16dde6639a89a080a524cebc4d4bedfe00ed0cac4b865a918d8"
	d := Download{URL: "https://example.com/tool.zip", Dest: `C:\Tools\tool.zip`, SHA256: strings.ToUpper(sum)}
	if err := d.Validate(); err != nil {
		t.Fatal(err)
	}
	for want, bad := range map[string]Download{
		"https address":   {URL: "http://example.com/a", Dest: d.Dest, SHA256: sum},
		"https address ":  {URL: "ftp://example.com/a", Dest: d.Dest, SHA256: sum, AllowHTTP: true},
		"https address  ": {URL: "https://example.com/a b", Dest: d.Dest, SHA256: sum},
		"dest":            {URL: d.URL, Dest: `relative\tool.zip`, SHA256: sum},
		"64 hex":          {URL: d.URL, Dest: d.Dest, SHA256: "abc"},
		"max_size_mb":     {URL: d.URL, Dest: d.Dest, SHA256: sum, MaxSizeMB: -1},
	} {
		if err := bad.Validate(); err == nil || !strings.Contains(err.Error(), strings.TrimSpace(want)) {
			t.Errorf("%+v: %v, want %q", bad, err, want)
		}
	}
	if err := (Download{URL: "http://mirror.local/a", Dest: d.Dest, SHA256: sum, AllowHTTP: true}).Validate(); err != nil {
		t.Errorf("http with allow_http: %v", err)
	}

	for name, c := range map[string]struct {
		answer map[string]any
		inSync bool
		err    string
	}{
		"missing":           {map[string]any{"kind": "missing"}, false, ""},
		"matching file":     {map[string]any{"kind": "file", "sha256": strings.ToUpper(sum)}, true, ""},
		"another file":      {map[string]any{"kind": "file", "sha256": "f" + sum[1:]}, false, ""},
		"a link":            {map[string]any{"kind": "link"}, false, ""},
		"a link on the way": {map[string]any{"kind": "missing", "link_on_way": `C:\Tools`}, false, ""},
		"a folder":          {map[string]any{"kind": "directory"}, false, "is a folder"},
	} {
		inSync, err := DownloadInSync(ctx, &fake{answers: []map[string]any{ok(c.answer)}}, d)
		if c.err != "" {
			if err == nil || !strings.Contains(err.Error(), c.err) {
				t.Errorf("%s: %v, want %s", name, err, c.err)
			}
			continue
		}
		if err != nil || inSync != c.inSync {
			t.Errorf("%s: in sync %v, %v", name, inSync, err)
		}
	}

	f := &fake{answers: []map[string]any{ok(map[string]any{"sha256": sum})}}
	if err := ApplyDownload(ctx, f, d, time.Minute); err != nil {
		t.Fatal(err)
	}
	a := args(f, 0)
	if a["path"] != d.Dest || a["url"] != d.URL || a["sha256"] != sum || a["allow_http"] != false || a["max_bytes"] != float64(DefaultMaxSizeMB<<20) {
		t.Errorf("sent %v", a)
	}
	f = &fake{answers: []map[string]any{ok(map[string]any{"sha256": "f" + sum[1:]})}}
	if err := ApplyDownload(ctx, f, Download{URL: d.URL, Dest: d.Dest, SHA256: sum, MaxSizeMB: 5}, time.Minute); err == nil || !strings.Contains(err.Error(), "was written with SHA-256") {
		t.Errorf("a result with another hash: %v", err)
	}
	if args(f, 0)["max_bytes"] != float64(5<<20) {
		t.Errorf("max_bytes for max_size_mb 5: %v", args(f, 0)["max_bytes"])
	}
}
