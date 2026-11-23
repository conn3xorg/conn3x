// Copyright (c) The Conn3x Authors
// SPDX-License-Identifier: MPL-2.0

package pack

import (
	"context"
	"strings"
	"testing"

	"github.com/opentofu/opentofu/internal/conn3x/transport/ssh"
)

func TestValidate(t *testing.T) {
	for _, good := range []Pack{
		{Paths: []string{"/var/log/app"}, Dest: "/backup/app.tgz"},
		{Paths: []string{"/var/log/*.log", "/etc/app"}, Dest: "/backup/a.zip", Format: "zip", Exclude: []string{"/var/log/*.gz"}, Mode: "0640"},
	} {
		if err := good.Validate(); err != nil {
			t.Errorf("%+v: %v", good, err)
		}
	}
	for _, bad := range []Pack{
		{Dest: "/backup/a.tgz"},
		{Paths: []string{"var/log"}, Dest: "/backup/a.tgz"},
		{Paths: []string{"/var/log/"}, Dest: "/backup/a.tgz"},
		{Paths: []string{"/var/../log"}, Dest: "/backup/a.tgz"},
		{Paths: []string{"/"}, Dest: "/backup/a.tgz"},
		{Paths: []string{"/var/*/app"}, Dest: "/backup/a.tgz"},
		{Paths: []string{"/var/log\nx"}, Dest: "/backup/a.tgz"},
		{Paths: []string{"/var/log"}, Dest: "backup/a.tgz"},
		{Paths: []string{"/var/log"}, Dest: "/backup/"},
		{Paths: []string{"/var/log"}, Dest: "/backup/a.tgz", Exclude: []string{"*.gz"}},
		{Paths: []string{"/var/log"}, Dest: "/backup/a.rar", Format: "rar"},
		{Paths: []string{"/var/log"}, Dest: "/backup/a.tgz", Mode: "644"},
	} {
		if err := bad.Validate(); err == nil {
			t.Errorf("%+v: no error", bad)
		}
	}
}

// Names in the archive start from the deepest directory holding every
// path, as they do in Ansible's archive module.
func TestRoot(t *testing.T) {
	for want, paths := range map[string][]string{
		"/var/log/":     {"/var/log/app"},
		"/var/log/app/": {"/var/log/app/*.log"},
		"/":             {"/etc"},
		"/a/":           {"/a/bc/x", "/a/bd/y"},
		"/srv/":         {"/srv/data", "/srv/logs/*.log"},
	} {
		if got := Root(paths); got != want {
			t.Errorf("%q: %q, want %q", paths, got, want)
		}
	}
}

// Only * and ? reach the shell bare; everything else is quoted.
func TestGlob(t *testing.T) {
	for in, want := range map[string]string{
		"/var/log/app":    `'/var/log/app'`,
		"/var/log/*.log":  `'/var/log/'*'.log'`,
		"/srv/it's ?$x*":  `'/srv/it'\''s '?'$x'*`,
		"/srv/[ab]$(id)*": `'/srv/[ab]$(id)'*`,
	} {
		if got := glob(in); got != want {
			t.Errorf("%q: %s, want %s", in, got, want)
		}
	}
}

// Each format packs with its own tar option, or zip, and checks first that
// the program it needs is there.
func TestCommand(t *testing.T) {
	for format, want := range map[string][]string{
		"":     {`command -v gzip `, `tar -c -f "$tmp" -z --no-recursion --verbatim-files-from -T "$list"`},
		"gz":   {`command -v gzip `, `tar -c -f "$tmp" -z --no-recursion`},
		"bz2":  {`command -v bzip2 `, `tar -c -f "$tmp" -j --no-recursion`},
		"xz":   {`command -v xz `, `tar -c -f "$tmp" -J --no-recursion`},
		"zstd": {`command -v zstd `, `tar -c -f "$tmp" --zstd --no-recursion`},
		"tar":  {`tar -c -f "$tmp" --no-recursion`},
		"zip":  {`command -v zip `, `zip -q -y -nw "$tmp" -@ < "$list"`},
	} {
		got := Pack{Format: format}.command()
		for _, w := range want {
			if !strings.Contains(got, w) {
				t.Errorf("%q: missing %q in\n%s", format, w, got)
			}
		}
		if (format == "zip") == strings.Contains(got, "GNU tar") {
			t.Errorf("%q: GNU tar check wrong in\n%s", format, got)
		}
	}
	if got := (Pack{Format: "tar"}).command(); strings.Contains(got, "command -v") {
		t.Errorf("tar checks for a compressor:\n%s", got)
	}
}

// The list takes the paths, globs bare, leaves out dest and every
// exclusion and what's below it, and names entries from the root.
func TestList(t *testing.T) {
	p := Pack{Paths: []string{"/srv/data", "/srv/logs/*.log"}, Dest: "/srv/out.tgz", Exclude: []string{"/srv/data/cache", "/srv/*.tmp"}}
	got := p.list()
	for _, w := range []string{
		"r='/srv/'\ncd -- \"$r\"\n",
		`for s in '/srv/data' '/srv/logs/'*'.log'; do`,
		`case "$f" in '/srv/out.tgz' | '/srv/data/cache' | '/srv/data/cache'/* | '/srv/'*'.tmp' | '/srv/'*'.tmp'/*) continue ;; esac`,
		`printf '%s\n' "${f#"$r"}"`,
		`LC_ALL=C sort -u > "$list"`,
	} {
		if !strings.Contains(got, w) {
			t.Errorf("missing %q in\n%s", w, got)
		}
	}
}

type host struct {
	out  string
	code int
	ran  []string
}

func (h *host) Run(_ context.Context, cmd string, _ []byte) (ssh.Result, error) {
	h.ran = append(h.ran, cmd)
	return ssh.Result{Stdout: []byte(h.out), ExitCode: h.code, Stderr: []byte("boom")}, nil
}

func TestRead(t *testing.T) {
	p := Pack{Paths: []string{"/srv/data"}, Dest: "/srv/out.tgz"}
	h := &host{out: "abc123\npresent\n"}
	sum, ok, err := Read(context.Background(), h, p)
	if err != nil || sum != "abc123" || !ok {
		t.Fatalf("%q %v %v", sum, ok, err)
	}
	if !strings.Contains(h.ran[0], "sha256sum") || strings.Contains(h.ran[0], "tar -c") {
		t.Errorf("read script:\n%s", h.ran[0])
	}
	if _, ok, _ := Read(context.Background(), &host{out: "abc\nabsent\n"}, p); ok {
		t.Error("absent read as present")
	}
	if _, _, err := Read(context.Background(), &host{out: "junk"}, p); err == nil {
		t.Error("junk output accepted")
	}
	if _, _, err := Read(context.Background(), &host{code: 1}, p); err == nil || !strings.Contains(err.Error(), "boom") {
		t.Errorf("failed read: %v", err)
	}
}

// Apply refuses a missing literal path up front, leaves globs to match
// what they match, sets the mode, and returns the sum it packed.
func TestApply(t *testing.T) {
	p := Pack{Paths: []string{"/srv/data", "/srv/logs/*.log"}, Dest: "/srv/out.tgz", Owner: "backup"}
	h := &host{out: "abc123\n"}
	sum, err := Apply(context.Background(), h, p)
	if err != nil || sum != "abc123" {
		t.Fatalf("%q %v", sum, err)
	}
	s := h.ran[0]
	for _, w := range []string{`[ -e '\''/srv/data'\'' ]`, `chmod 0600 "$tmp"`, `chown -- '\''backup'\'' "$tmp"`, `mv -fT -- "$tmp" "$p"`, `tar -c -f "$tmp" -z`} {
		if !strings.Contains(s, w) {
			t.Errorf("missing %q", w)
		}
	}
	if strings.Contains(s, `[ -e '\''/srv/logs/'\''*`) {
		t.Error("a glob is required to exist")
	}
	if _, err := Apply(context.Background(), h, Pack{Paths: []string{"rel"}, Dest: "/a"}); err == nil {
		t.Error("invalid pack applied")
	}
}
