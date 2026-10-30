// Copyright (c) The Conn3x Authors
// SPDX-License-Identifier: MPL-2.0

package provider

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"

	"github.com/zclconf/go-cty/cty"

	"github.com/opentofu/opentofu/internal/conn3x/modules/edit"
	"github.com/opentofu/opentofu/internal/conn3x/modules/moduletest"
)

// Edits to one file on one host take turns. Run together, each reads the
// file before the others write and the last write wins, as with a line
// step's for_each items (#139).
func TestEditsToOneFileTakeTurns(t *testing.T) {
	path := filepath.Join(t.TempDir(), "race.conf")
	const n = 12
	var wg sync.WaitGroup
	errs := make(chan error, n)
	for i := range n {
		wg.Add(1)
		go func() {
			defer wg.Done()
			h := &hostConn{runner: moduletest.Local{}, rootKey: "web1"}
			l := edit.Line{Line: fmt.Sprintf("k%d=%d", i, i)}
			errs <- editFile(context.Background(), h, path, true, func(s string) (string, error) { return edit.ApplyLine(s, l) })
		}()
	}
	wg.Wait()
	close(errs)
	for err := range errs {
		if err != nil {
			t.Fatal(err)
		}
	}
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	for i := range n {
		if want := fmt.Sprintf("k%d=%d", i, i); !strings.Contains(string(b), want+"\n") {
			t.Errorf("%s is missing %q; got:\n%s", path, want, b)
		}
	}
}

func editPlanned(t *testing.T, k editKind, set map[string]cty.Value) cty.Value {
	t.Helper()
	ty := k.schema().Block.ImpliedType()
	vals := map[string]cty.Value{}
	for name, at := range ty.AttributeTypes() {
		vals[name] = cty.NullVal(at)
	}
	for name, v := range set {
		vals[name] = v
	}
	return cty.ObjectVal(vals)
}

// Writing through a link leaves the link, and the target's mode, alone.
func TestIniWritesThroughLinksAndKeepsTheMode(t *testing.T) {
	dir := t.TempDir()
	real, link := filepath.Join(dir, "real.ini"), filepath.Join(dir, "link.ini")
	if err := os.WriteFile(real, []byte("# keep\n[a]\nx = 1\n"), 0o640); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(real, 0o640); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(real, link); err != nil {
		t.Fatal(err)
	}
	h := &hostConn{runner: moduletest.Local{}, rootKey: "web1"}
	v := editPlanned(t, iniKind, map[string]cty.Value{"path": cty.StringVal(link), "section": cty.StringVal("a"), "option": cty.StringVal("x"), "value": cty.StringVal("2")})
	target := iniKind.target(context.Background(), h, v)
	if err := editFile(context.Background(), h, target, false, iniKind.edit(v)); err != nil {
		t.Fatal(err)
	}
	if fi, err := os.Lstat(link); err != nil || fi.Mode()&os.ModeSymlink == 0 {
		t.Fatalf("link was replaced: %v %v", fi, err)
	}
	fi, err := os.Stat(real)
	if err != nil || fi.Mode().Perm() != 0o640 {
		t.Fatalf("mode: %v %v", fi, err)
	}
	if b, _ := os.ReadFile(real); string(b) != "# keep\n[a]\nx = 2\n" {
		t.Fatalf("content: %q", b)
	}
}

func TestEditValidation(t *testing.T) {
	str := cty.StringVal
	for name, tc := range map[string]struct {
		k   editKind
		set map[string]cty.Value
		ok  bool
	}{
		"ini":                    {iniKind, map[string]cty.Value{"option": str("a"), "value": str("b")}, true},
		"ini with no value":      {iniKind, map[string]cty.Value{"option": str("a")}, false},
		"ini empty value":        {iniKind, map[string]cty.Value{"option": str("a"), "value": str("")}, true},
		"ini absent":             {iniKind, map[string]cty.Value{"option": str("a"), "state": str("absent")}, true},
		"replace":                {replaceKind, map[string]cty.Value{"regexp": str("a"), "replace": str("b")}, true},
		"replace create":         {replaceKind, map[string]cty.Value{"regexp": str("a"), "replace": str("b"), "create": cty.True}, false},
		"replace on_remove":      {replaceKind, map[string]cty.Value{"regexp": str("a"), "replace": str("b"), "on_remove": str("delete")}, false},
		"replace that can't end": {replaceKind, map[string]cty.Value{"regexp": str("a"), "replace": str("aa")}, false},
	} {
		tc.set["path"] = str("/etc/a")
		diags := tc.k.validate(editPlanned(t, tc.k, tc.set))
		if diags.HasErrors() == tc.ok {
			t.Errorf("%s: diags %v", name, diags)
		}
	}
}
