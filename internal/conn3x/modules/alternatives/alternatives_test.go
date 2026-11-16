// Copyright (c) The Conn3x Authors
// SPDX-License-Identifier: MPL-2.0

package alternatives

import (
	"context"
	"strings"
	"testing"

	"github.com/opentofu/opentofu/internal/conn3x/transport/ssh"
)

func TestValidate(t *testing.T) {
	for _, ok := range []Alternative{
		{Name: "editor", Path: "/usr/bin/vim.basic"},
		{Name: "libblas.so.3-x86_64-linux-gnu", Path: "/usr/lib/x86_64-linux-gnu/openblas-pthread/libblas.so.3", Link: "/usr/lib/x86_64-linux-gnu/libblas.so.3", Priority: "-100"},
	} {
		if err := ok.Validate(); err != nil {
			t.Errorf("%+v: %v", ok, err)
		}
	}
	for _, bad := range []Alternative{
		{Name: "", Path: "/usr/bin/vim"},
		{Name: "-editor", Path: "/usr/bin/vim"},
		{Name: "ed itor", Path: "/usr/bin/vim"},
		{Name: "editor", Path: "usr/bin/vim"},
		{Name: "editor", Path: "/usr/bin/vim; rm -rf /"},
		{Name: "editor", Path: "/usr/bin/vim", Link: "/usr/bin/"},
		{Name: "editor", Path: "/usr/bin/vim", Priority: "high"},
	} {
		if bad.Validate() == nil {
			t.Errorf("accepted %+v", bad)
		}
	}
}

const debianDisplay = `editor - manual mode
  link best version is /usr/bin/vim.basic
  link currently points to /bin/nano
  link editor is /usr/bin/editor
  slave editor.1.gz is /usr/share/man/man1/editor.1.gz
/bin/ed - priority -100
  slave editor.1.gz: /usr/share/man/man1/ed.1.gz
/bin/nano - priority 40
/usr/bin/vim.basic - priority 30
`

const rockyDisplay = `python - status is auto.
 link currently points to /usr/bin/python3
/usr/bin/python3 - priority 1000
 slave unversioned-python-man: /usr/share/man/man1/python3.1.gz
/usr/bin/python3.12 - priority 10
Current ` + "`best'" + ` version is /usr/bin/python3.
`

func TestParseDisplay(t *testing.T) {
	d := parseDisplay(debianDisplay)
	if !d.Registered || d.Current != "/bin/nano" || d.Link != "/usr/bin/editor" || d.Priority["/bin/ed"] != "-100" || d.Priority["/usr/bin/vim.basic"] != "30" || len(d.Priority) != 3 {
		t.Errorf("debian: %+v", d)
	}
	r := parseDisplay(rockyDisplay)
	if !r.Registered || r.Current != "/usr/bin/python3" || r.Link != "" || r.Priority["/usr/bin/python3.12"] != "10" || len(r.Priority) != 2 {
		t.Errorf("rocky: %+v", r)
	}
	a := Alternative{Name: "editor", Path: "/usr/bin/vim.basic"}
	if a.InSync(d) {
		t.Error("in sync while nano is current")
	}
	a.Path = "/bin/nano"
	if !a.InSync(d) {
		t.Error("out of sync with nano current")
	}
	a.Priority = "50"
	if a.InSync(d) {
		t.Error("in sync with another priority")
	}
}

// fakeHost answers --display with display and records the rest.
type fakeHost struct {
	display string
	exit    int
	stderr  string
	ran     []string
}

func (h *fakeHost) Run(_ context.Context, cmd string, _ []byte) (ssh.Result, error) {
	if strings.Contains(cmd, "--display") {
		return ssh.Result{Stdout: []byte(h.display), Stderr: []byte(h.stderr), ExitCode: h.exit}, nil
	}
	h.ran = append(h.ran, cmd)
	return ssh.Result{}, nil
}

func TestApplyDoesOnlyWhatIsMissing(t *testing.T) {
	ctx := context.Background()
	// Registered, another choice current: set only.
	h := &fakeHost{display: debianDisplay}
	if err := Apply(ctx, h, Alternative{Name: "editor", Path: "/usr/bin/vim.basic"}); err != nil {
		t.Fatal(err)
	}
	if len(h.ran) != 1 || strings.Contains(h.ran[0], "--install") || !strings.Contains(h.ran[0], `--set 'editor' '/usr/bin/vim.basic'`) {
		t.Errorf("ran %q", h.ran)
	}
	// Not registered, no link given: Debian prints the link, so use it.
	h = &fakeHost{display: debianDisplay}
	if err := Apply(ctx, h, Alternative{Name: "editor", Path: "/usr/bin/emacs", Priority: "20"}); err != nil {
		t.Fatal(err)
	}
	if len(h.ran) != 1 || !strings.Contains(h.ran[0], `--install '/usr/bin/editor' 'editor' '/usr/bin/emacs' 20`) || !strings.Contains(h.ran[0], `--set 'editor' '/usr/bin/emacs'`) {
		t.Errorf("ran %q", h.ran)
	}
	// Name unknown to the tool, and no link: nothing to register it with.
	h = &fakeHost{exit: 2, stderr: "update-alternatives: error: no alternatives for tool"}
	if err := Apply(ctx, h, Alternative{Name: "tool", Path: "/usr/local/bin/a"}); err == nil || !strings.Contains(err.Error(), "needs link") {
		t.Errorf("err = %v", err)
	}
	if err := Apply(ctx, h, Alternative{Name: "tool", Path: "/usr/local/bin/a", Link: "/usr/local/bin/tool"}); err != nil {
		t.Fatal(err)
	}
	if len(h.ran) != 1 || !strings.Contains(h.ran[0], `--install '/usr/local/bin/tool' 'tool' '/usr/local/bin/a' 50`) {
		t.Errorf("ran %q", h.ran)
	}
	// Any other failure of --display is an error, not an empty name.
	h = &fakeHost{exit: 2, stderr: "alternatives: error reading link: Permission denied"}
	if _, err := Read(ctx, h, Alternative{Name: "tool"}); err == nil {
		t.Error("read swallowed the error")
	}
	// Delete skips a path that isn't registered, so the Red Hat tool's
	// exit 2 for it never surfaces.
	h = &fakeHost{display: rockyDisplay}
	if err := Delete(ctx, h, Alternative{Name: "python", Path: "/usr/bin/python2"}); err != nil || len(h.ran) != 0 {
		t.Errorf("delete: %v, ran %q", err, h.ran)
	}
	if err := Delete(ctx, h, Alternative{Name: "python", Path: "/usr/bin/python3.12"}); err != nil || len(h.ran) != 1 || !strings.Contains(h.ran[0], "--remove 'python' '/usr/bin/python3.12'") {
		t.Errorf("delete: %v, ran %q", err, h.ran)
	}
}

// Only manual mode at Path is in sync: in auto mode a package installed
// later with a higher priority takes the name over.
func TestManualModeOnly(t *testing.T) {
	d, r := parseDisplay(debianDisplay), parseDisplay(rockyDisplay)
	if !d.Manual || r.Manual {
		t.Fatalf("mode: debian manual=%v, rocky manual=%v", d.Manual, r.Manual)
	}
	for display, manual := range map[string]bool{
		"c3x - auto mode\n": false, "c3x - manual mode\n": true,
		"c3x - status is auto.\n": false, "c3x - status is manual.\n": true,
	} {
		if got := parseDisplay(display).Manual; got != manual {
			t.Errorf("%q: manual=%v", display, got)
		}
	}
	a := Alternative{Name: "python", Path: "/usr/bin/python3"}
	if a.InSync(r) {
		t.Error("auto mode at path counted as in sync")
	}
	r.Manual = true
	if !a.InSync(r) {
		t.Error("manual mode at path isn't in sync")
	}
}
