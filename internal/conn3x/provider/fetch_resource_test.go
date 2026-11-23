// Copyright (c) The Conn3x Authors
// SPDX-License-Identifier: MPL-2.0

package provider

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/zclconf/go-cty/cty"
)

func TestFetchValidate(t *testing.T) {
	for name, attrs := range map[string]map[string]cty.Value{
		"relative src": {"src": cty.StringVal("etc/app.pem"), "dest": cty.StringVal("app.pem")},
		"dest dir":     {"src": cty.StringVal("/etc/app.pem"), "dest": cty.StringVal("certs/")},
		"on_remove":    {"src": cty.StringVal("/etc/app.pem"), "dest": cty.StringVal("app.pem"), "on_remove": cty.StringVal("purge")},
	} {
		if diags := validateFetch(objFor(fetchSchema(), attrs)); !diags.HasErrors() {
			t.Errorf("%s: no error", name)
		}
	}
	ok := map[string]cty.Value{"src": cty.StringVal("/etc/app.pem"), "dest": cty.StringVal("certs/web1.pem")}
	if diags := validateFetch(objFor(fetchSchema(), ok)); diags.HasErrors() {
		t.Error(diags.Err())
	}
}

// The copy is owner-only, its directory too, and a second write replaces
// it without leaving a temporary file behind.
func TestWriteFetched(t *testing.T) {
	dir := t.TempDir()
	dest := filepath.Join(dir, "certs", "web1.pem")
	for _, content := range []string{"first\n", "second\n"} {
		if err := writeFetched(dest, []byte(content)); err != nil {
			t.Fatal(err)
		}
		if got, _ := os.ReadFile(dest); string(got) != content {
			t.Errorf("content %q, want %q", got, content)
		}
	}
	if fi, _ := os.Stat(dest); fi.Mode().Perm() != 0o600 {
		t.Errorf("file mode %v", fi.Mode())
	}
	if fi, _ := os.Stat(filepath.Dir(dest)); fi.Mode().Perm() != 0o700 {
		t.Errorf("directory mode %v", fi.Mode())
	}
	if left, _ := os.ReadDir(filepath.Dir(dest)); len(left) != 1 {
		t.Errorf("left behind: %v", left)
	}
}
