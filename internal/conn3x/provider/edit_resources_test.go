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

// Writing through a link leaves the link, and the target's mode, alone, for
// every kind of edit. Reading it back says in sync, so a second plan is empty.
func TestEditsWriteThroughLinksAndKeepTheMode(t *testing.T) {
	str := cty.StringVal
	for name, tc := range map[string]struct {
		k    editKind
		set  map[string]cty.Value
		want string
	}{
		"line":    {lineKind, map[string]cty.Value{"regexp": str("^x ="), "line": str("x = 2")}, "# keep\n[a]\nx = 2\n"},
		"block":   {blockKind, map[string]cty.Value{"content": str("y = 3")}, "# keep\n[a]\nx = 1\n# BEGIN CONN3X MANAGED BLOCK\ny = 3\n# END CONN3X MANAGED BLOCK\n"},
		"ini":     {iniKind, map[string]cty.Value{"section": str("a"), "option": str("x"), "value": str("2")}, "# keep\n[a]\nx = 2\n"},
		"replace": {replaceKind, map[string]cty.Value{"regexp": str("x = 1"), "replace": str("x = 2")}, "# keep\n[a]\nx = 2\n"},
	} {
		t.Run(name, func(t *testing.T) {
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
			ctx := context.Background()
			h := &hostConn{runner: moduletest.Local{}, rootKey: "web1"}
			tc.set["path"] = str(link)
			v := editPlanned(t, tc.k, tc.set)
			target, err := editTarget(ctx, h, v.GetAttr("path").AsString())
			if err != nil {
				t.Fatal(err)
			}
			if err := editFile(ctx, h, target, false, tc.k.edit(v)); err != nil {
				t.Fatal(err)
			}
			if fi, err := os.Lstat(link); err != nil || fi.Mode()&os.ModeSymlink == 0 {
				t.Fatalf("link was replaced: %v %v", fi, err)
			}
			fi, err := os.Stat(real)
			if err != nil || fi.Mode().Perm() != 0o640 {
				t.Fatalf("mode: %v %v", fi, err)
			}
			b, _ := os.ReadFile(real)
			if string(b) != tc.want {
				t.Fatalf("content: %q", b)
			}
			// What read compares, to say whether a plan has anything to do.
			if again, err := tc.k.edit(v)(string(b)); err != nil || again != string(b) {
				t.Fatalf("not in sync after the edit: %q %v", again, err)
			}
		})
	}
}

// A regular file, or one not there yet, is written where it says.
func TestEditTargetOfAPlainPath(t *testing.T) {
	dir := t.TempDir()
	if resolved, err := filepath.EvalSymlinks(dir); err == nil {
		dir = resolved // the temp dir itself is behind a link on a Mac
	}
	plain := filepath.Join(dir, "plain.conf ")
	if err := os.WriteFile(plain, []byte("x\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	h := &hostConn{runner: moduletest.Local{}, rootKey: "web1"}
	for _, p := range []string{plain, filepath.Join(dir, "new.conf"), filepath.Join(dir, "no", "dir", "new.conf")} {
		got, err := editTarget(context.Background(), h, editPlanned(t, lineKind, map[string]cty.Value{"path": cty.StringVal(p)}).GetAttr("path").AsString())
		if err != nil || got != p {
			t.Errorf("%q: got %q, %v", p, got, err)
		}
	}
}

// Falling back to the link's own path would replace it with a file of mode
// 0777, so a link that can't be resolved stops the edit.
func TestEditTargetRefusesALinkItCantFollow(t *testing.T) {
	loop := filepath.Join(t.TempDir(), "loop")
	if err := os.Symlink(loop, loop); err != nil {
		t.Fatal(err)
	}
	h := &hostConn{runner: moduletest.Local{}, rootKey: "web1"}
	if got, err := editTarget(context.Background(), h, editPlanned(t, lineKind, map[string]cty.Value{"path": cty.StringVal(loop)}).GetAttr("path").AsString()); err == nil {
		t.Fatalf("got %q, want an error", got)
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
