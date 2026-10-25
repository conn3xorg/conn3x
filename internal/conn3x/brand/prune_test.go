// Copyright (c) The Conn3x Authors
// SPDX-License-Identifier: MPL-2.0

package brand

import (
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

func TestPruneBackends(t *testing.T) {
	src, err := os.ReadFile(filepath.Join("..", "..", "backend", "init", "init.go"))
	if err != nil {
		t.Fatal(err)
	}
	out, err := pruneBackends(src)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := parser.ParseFile(token.NewFileSet(), "init.go", out, 0); err != nil {
		t.Fatalf("pruned init.go does not parse: %v", err)
	}
	got := string(out)
	for _, name := range []string{"cos", "oss"} {
		if strings.Contains(got, "remote-state/"+name+`"`) {
			t.Errorf("%s is still imported", name)
		}
		if !regexp.MustCompile(`"` + name + `":\s+` + "`" + `The "` + name + `" backend is not included in Conn3x`).MatchString(got) {
			t.Errorf("%s has no removed-backend message", name)
		}
	}
	for _, kept := range []string{"remote-state/kubernetes", "remote-state/s3", "remote-state/gcs", "remote-state/azure", "remote-state/consul", "remote-state/pg", "remote-state/http"} {
		if !strings.Contains(got, kept) {
			t.Errorf("%s was pruned", kept)
		}
	}
	if _, err := pruneBackends([]byte("package init\n")); err == nil {
		t.Error("pruning a file without the backends succeeded; upstream changes must fail loudly")
	}
}
