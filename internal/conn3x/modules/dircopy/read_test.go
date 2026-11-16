// Copyright (c) The Conn3x Authors
// SPDX-License-Identifier: MPL-2.0

package dircopy

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/opentofu/opentofu/internal/conn3x/transport/ssh"
)

// canned answers every command with res, and records them.
type canned struct {
	res  ssh.Result
	err  error
	cmds []string
}

func (c *canned) Run(_ context.Context, cmd string, _ []byte) (ssh.Result, error) {
	c.cmds = append(c.cmds, cmd)
	return c.res, c.err
}

// Read parses find's records as GNU find prints them on a host, so it's
// checked here without one.
func TestReadParses(t *testing.T) {
	ctx := context.Background()
	out := "present\n" +
		"644 root www index.html\x00" + "600 app app a dir/with space.txt\x00" + "bad record\x00" +
		"\x00" +
		"aaaa  ./index.html\x00" + "bbbb  ./a dir/with space.txt\x00" + "cccc  ./gone\x00" + "no separator\x00"
	got, err := Read(ctx, &canned{res: ssh.Result{Stdout: []byte(out)}}, "/srv/site")
	if err != nil {
		t.Fatal(err)
	}
	want := map[string]Remote{
		"index.html":           {Sum: "aaaa", Mode: "0644", Owner: "root", Group: "www"},
		"a dir/with space.txt": {Sum: "bbbb", Mode: "0600", Owner: "app", Group: "app"},
	}
	if len(got) != len(want) || got["index.html"] != want["index.html"] || got["a dir/with space.txt"] != want["a dir/with space.txt"] {
		t.Errorf("got %+v", got)
	}

	if got, err := Read(ctx, &canned{res: ssh.Result{Stdout: []byte("missing\n")}}, "/srv/site"); err != nil || len(got) != 0 {
		t.Errorf("missing: %v, %v", got, err)
	}
	// An empty directory lists no records, only the NUL that ends the list.
	if got, err := Read(ctx, &canned{res: ssh.Result{Stdout: []byte("present\n\x00")}}, "/srv/site"); err != nil || len(got) != 0 {
		t.Errorf("empty: %v, %v", got, err)
	}
	if _, err := Read(ctx, &canned{res: ssh.Result{Stdout: []byte("present\n644 a b f\x00")}}, "/srv/site"); err == nil || err.Error() != "reading /srv/site: unexpected output" {
		t.Errorf("truncated: %v", err)
	}
	if _, err := Read(ctx, &canned{res: ssh.Result{ExitCode: 1, Stderr: []byte("refusing /srv/site\n")}}, "/srv/site"); err == nil || err.Error() != "reading /srv/site: refusing /srv/site" {
		t.Errorf("refused: %v", err)
	}
	if _, err := Read(ctx, &canned{err: errors.New("down")}, "/srv/site"); err == nil || err.Error() != "down" {
		t.Errorf("runner: %v", err)
	}
}

func TestDiff(t *testing.T) {
	sums := map[string]string{"a": "1", "b": "2", "c": "3", "d": "4"}
	have := map[string]Remote{
		"a": {Sum: "1", Mode: "0644", Owner: "www", Group: "www"},
		"b": {Sum: "2", Mode: "0600", Owner: "www", Group: "www"},
		"c": {Sum: "3", Mode: "0644", Owner: "root", Group: "www"},
		"d": {Sum: "4", Mode: "0644", Owner: "www", Group: "root"},
		"x": {Sum: "9", Mode: "0644", Owner: "www", Group: "www"},
	}
	p := Copy{Mode: "0644", Owner: "www", Group: "www"}.Diff(sums, have)
	if strings.Join(p.Write, ",") != "b,c,d" || len(p.Remove) != 0 {
		t.Errorf("mode, owner and group: %+v", p)
	}
	if p := (Copy{Mode: "0644"}).Diff(map[string]string{"a": "1"}, have); !p.Empty() {
		t.Errorf("no owner or group set: %+v", p)
	}
	if p := (Copy{Mode: "0644", Delete: true}).Diff(map[string]string{"a": "1", "new": "5"}, have); strings.Join(p.Write, ",") != "new" || strings.Join(p.Remove, ",") != "b,c,d,x" || p.Empty() {
		t.Errorf("delete: %+v", p)
	}
}

func TestApplyErrorsNameTheFile(t *testing.T) {
	ctx := context.Background()
	c := Copy{Dest: "/srv/site", Mode: "0644"}
	r := &canned{res: ssh.Result{ExitCode: 1, Stderr: []byte("disk full")}}
	if err := c.Apply(ctx, r, map[string][]byte{"a": []byte("x")}, Plan{Write: []string{"a"}, Remove: []string{"b"}}); err == nil || !strings.HasPrefix(err.Error(), "writing /srv/site/a: ") || len(r.cmds) != 1 {
		t.Errorf("write: %v after %d commands", err, len(r.cmds))
	}
	if err := c.Apply(ctx, r, nil, Plan{Remove: []string{"b"}}); err == nil || err.Error() != "removing /srv/site/b: disk full" {
		t.Errorf("remove: %v", err)
	}
	if err := c.Apply(ctx, r, nil, Plan{}); err != nil {
		t.Errorf("empty plan: %v", err)
	}
}

func TestLocal(t *testing.T) {
	src := t.TempDir()
	write(t, filepath.Join(src, "a"), []byte("x"))
	write(t, filepath.Join(src, "d/b"), []byte("yy"))
	files, err := Copy{Source: src}.Local()
	if err != nil || len(files) != 2 || string(files["a"]) != "x" || string(files["d/b"]) != "yy" {
		t.Errorf("got %q, %v", files, err)
	}
	if s := Sums(files); s["a"] != "2d711642b726b04401627ca9fbac32f5c8530fb1903cc4db02258717921a4881" {
		t.Errorf("sum of x: %s", s["a"])
	}
	if _, err := (Copy{Source: filepath.Join(src, "none")}).Local(); err == nil || !strings.HasPrefix(err.Error(), "reading source ") {
		t.Errorf("missing source: %v", err)
	}
	if os.Geteuid() != 0 {
		if err := os.Chmod(filepath.Join(src, "a"), 0); err != nil {
			t.Fatal(err)
		}
		if _, err := (Copy{Source: src}).Local(); err == nil {
			t.Error("read an unreadable file")
		}
	}
}
