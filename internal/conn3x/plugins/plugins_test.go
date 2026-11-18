// Copyright (c) The Conn3x Authors
// SPDX-License-Identifier: MPL-2.0

package plugins

import (
	"os"
	"path/filepath"
	"testing"
)

const lockWithProvider = `provider "registry.opentofu.org/hashicorp/null" {
  version = "3.2.0"
  hashes  = ["h1:aaaa"]
}
`

func TestInstalled(t *testing.T) {
	for _, tc := range []struct {
		name    string
		files   map[string]string // path in the directory: contents; a trailing / makes a directory
		dataDir string            // TF_DATA_DIR, relative to the directory
		want    string
	}{
		{name: "nothing", want: ""},
		{name: "a lock with no providers", files: map[string]string{".terraform.lock.hcl": "# empty\n"}, want: ""},
		{name: "a lock naming a provider", files: map[string]string{".terraform.lock.hcl": lockWithProvider}, want: ".terraform.lock.hcl"},
		{name: "a lock that doesn't parse", files: map[string]string{".terraform.lock.hcl": "provider {"}, want: ".terraform.lock.hcl"},
		{name: "an empty providers directory", files: map[string]string{".terraform/providers/": ""}, want: ""},
		{name: "a providers directory with something in it", files: map[string]string{".terraform/providers/registry.opentofu.org/": ""}, want: ".terraform/providers"},
		{name: "providers under TF_DATA_DIR", files: map[string]string{"state/providers/x/": ""}, dataDir: "state", want: "state/providers"},
		{name: "providers in .terraform ignored when TF_DATA_DIR is elsewhere", files: map[string]string{".terraform/providers/x/": ""}, dataDir: "state", want: ""},
	} {
		t.Run(tc.name, func(t *testing.T) {
			dir := t.TempDir()
			for path, body := range tc.files {
				p := filepath.Join(dir, filepath.FromSlash(path))
				if path[len(path)-1] == '/' {
					if err := os.MkdirAll(p, 0o755); err != nil {
						t.Fatal(err)
					}
					continue
				}
				if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
					t.Fatal(err)
				}
				if err := os.WriteFile(p, []byte(body), 0o644); err != nil {
					t.Fatal(err)
				}
			}
			t.Setenv("TF_DATA_DIR", tc.dataDir)
			want := tc.want
			if want != "" && want != ".terraform.lock.hcl" {
				want = filepath.Join(dir, filepath.FromSlash(want))
			}
			if got := Installed(dir); got != want {
				t.Errorf("Installed = %q, want %q", got, want)
			}
		})
	}
}
