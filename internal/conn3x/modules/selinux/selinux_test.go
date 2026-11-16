// Copyright (c) The Conn3x Authors
// SPDX-License-Identifier: MPL-2.0

package selinux

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/opentofu/opentofu/internal/conn3x/modules"
	"github.com/opentofu/opentofu/internal/conn3x/transport/ssh"
)

func TestValidate(t *testing.T) {
	if err := ValidateBoolean("httpd_can_network_connect"); err != nil {
		t.Fatal(err)
	}
	for _, bad := range []string{"", "httpd can", "x;reboot", "../x"} {
		if ValidateBoolean(bad) == nil {
			t.Errorf("accepted boolean %q", bad)
		}
	}
	if err := (Fcontext{Target: "/srv/www(/.*)?", Type: "httpd_sys_content_t"}).Validate(); err != nil {
		t.Fatal(err)
	}
	for _, bad := range []Fcontext{
		{Target: "srv/www", Type: "httpd_sys_content_t"},
		{Target: "/srv/www", Type: "httpd sys"},
		{Target: "/srv/www\n/etc", Type: "httpd_sys_content_t"},
		{Target: "/srv/www", Type: ""},
	} {
		if bad.Validate() == nil {
			t.Errorf("accepted %+v", bad)
		}
	}
}

func TestRestorePath(t *testing.T) {
	for target, want := range map[string]string{
		"/srv/www(/.*)?":          "/srv/www",
		"/srv/www":                "/srv/www",
		"/var/lib/app/[^/]+\\.db": "/var/lib/app",
		"/(.*)?":                  "",
		"/opt/my.app(/.*)?":       "/opt/my.app",
		"/srv/www.*":              "/srv",
	} {
		if got := (Fcontext{Target: target}).RestorePath(); got != want {
			t.Errorf("RestorePath(%q) = %q, want %q", target, got, want)
		}
	}
}

func TestParseBoolean(t *testing.T) {
	for in, want := range map[string]bool{"1 1": true, "0 0": false, "1 0": true} {
		got, err := parseBoolean(in)
		if err != nil || got != want {
			t.Errorf("parseBoolean(%q) = %v, %v", in, got, err)
		}
	}
	if _, err := parseBoolean(""); err == nil {
		t.Error("accepted empty input")
	}
}

func TestLocalType(t *testing.T) {
	out := `/srv/www(/.*)?                                     all files          system_u:object_r:httpd_sys_content_t:s0
/srv/www/cgi(/.*)?                                 all files          system_u:object_r:httpd_sys_script_exec_t:s0
`
	if got := localType(out, "/srv/www(/.*)?"); got != "httpd_sys_content_t" {
		t.Errorf("got %q", got)
	}
	if got := localType(out, "/srv"); got != "" {
		t.Errorf("matched a prefix: %q", got)
	}
}

// The name goes into a path, so ReadBoolean checks it whoever calls.
func TestReadBooleanValidatesItsName(t *testing.T) {
	if _, err := ReadBoolean(context.Background(), nil, "x; reboot"); err == nil {
		t.Fatal("read a boolean with an invalid name")
	}
}

func TestWithMode(t *testing.T) {
	for in, want := range map[string]string{
		"# comment\nSELINUX=enforcing\nSELINUXTYPE=targeted\n": "# comment\nSELINUX=permissive\nSELINUXTYPE=targeted\n",
		"SELINUX = disabled\nSELINUX=enforcing\n":              "SELINUX = disabled\nSELINUX=permissive\n",
		"SELINUXTYPE=targeted":                                 "SELINUXTYPE=targeted\nSELINUX=permissive\n",
		"# SELINUX=enforcing\n":                                "# SELINUX=enforcing\nSELINUX=permissive\n",
	} {
		if got := withMode(in, "permissive"); got != want {
			t.Errorf("withMode(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestModeState(t *testing.T) {
	for _, c := range []struct {
		s             ModeState
		match, reboot bool
	}{
		{ModeState{"enforcing", "enforcing"}, true, false},
		{ModeState{"enforcing", "permissive"}, false, false},
		{ModeState{"permissive", "enforcing"}, false, false},
		{ModeState{"enforcing", "disabled"}, true, true},
		{ModeState{"disabled", "disabled"}, false, true},
	} {
		if c.s.Matches("enforcing") != c.match || c.s.RebootRequired("enforcing") != c.reboot {
			t.Errorf("%+v: match %v, reboot %v", c.s, c.s.Matches("enforcing"), c.s.RebootRequired("enforcing"))
		}
	}
	if ValidateMode("disabled") == nil || ValidateMode("Enforcing") == nil || ValidateMode("permissive") != nil {
		t.Error("ValidateMode")
	}
}

// host is an SELinux host. It reads the config file natively, takes a
// write to it and setenforce as changes, and answers anything else from the
// first key of out the command holds.
type host struct {
	config  *string // nil when there's no config file
	enforce string  // what /sys/fs/selinux/enforce holds, "off" when SELinux is
	out     map[string]ssh.Result
	ran     []string
}

func (h *host) ReadFile(_ context.Context, p string) (modules.FileStat, error) {
	if p != ConfigFile || h.config == nil {
		return modules.FileStat{}, nil
	}
	return modules.FileStat{Exists: true, Regular: true, Mode: 0o644, Owner: "root", Group: "root", Content: []byte(*h.config)}, nil
}

func (h *host) Run(_ context.Context, cmd string, stdin []byte) (ssh.Result, error) {
	h.ran = append(h.ran, cmd)
	switch {
	case stdin != nil:
		c := string(stdin)
		h.config = &c
		return ssh.Result{}, nil
	case strings.Contains(cmd, "/sys/fs/selinux/enforce"):
		return ssh.Result{Stdout: []byte(h.enforce + "\n")}, nil
	}
	for k, v := range h.out {
		if strings.Contains(cmd, k) {
			return v, nil
		}
	}
	if v, ok := strings.CutPrefix(cmd, "setenforce "); ok {
		h.enforce = v
	}
	return ssh.Result{}, nil
}

var ctx = context.Background()

func ptr(s string) *string { return &s }

func TestReadMode(t *testing.T) {
	for enforce, want := range map[string]ModeState{
		"1":   {"enforcing", "enforcing"},
		"0":   {"enforcing", "permissive"},
		"off": {"enforcing", "disabled"},
	} {
		// The loader takes the last line, in any case.
		h := &host{config: ptr("SELINUX=permissive\nSELINUX=Enforcing\nSELINUXTYPE=targeted\n"), enforce: enforce}
		if got, err := ReadMode(ctx, h); err != nil || got != want {
			t.Errorf("enforce %s: %+v, %v; want %+v", enforce, got, err, want)
		}
	}
	if _, err := ReadMode(ctx, &host{}); err == nil || !strings.Contains(err.Error(), "SELinux isn't installed") {
		t.Errorf("no config file: %v", err)
	}
	if _, err := ReadMode(ctx, &failing{config: "SELINUX=enforcing\n"}); err == nil || err.Error() != "cat: Permission denied" {
		t.Errorf("unreadable enforce: %v", err)
	}
}

// failing has a config file and fails every command.
type failing struct{ config string }

func (f *failing) ReadFile(context.Context, string) (modules.FileStat, error) {
	return modules.FileStat{Exists: true, Regular: true, Mode: 0o644, Content: []byte(f.config)}, nil
}

func (f *failing) Run(context.Context, string, []byte) (ssh.Result, error) {
	return ssh.Result{ExitCode: 1, Stderr: []byte("cat: Permission denied")}, nil
}

func TestApplyMode(t *testing.T) {
	for name, c := range map[string]struct {
		mode, config, enforce string
		wantConfig            string // "" when it's left alone
		setenforce            string // "" when it isn't run
		reboot                bool
	}{
		"to permissive":     {"permissive", "SELINUX=enforcing\nSELINUXTYPE=targeted\n", "1", "SELINUX=permissive\nSELINUXTYPE=targeted\n", "setenforce 0", false},
		"in sync":           {"enforcing", "SELINUX=enforcing\n", "1", "", "", false},
		"only running":      {"enforcing", "SELINUX=enforcing\n", "0", "", "setenforce 1", false},
		"only config":       {"enforcing", "SELINUX=permissive\n", "1", "SELINUX=enforcing\n", "", false},
		"line added":        {"permissive", "SELINUXTYPE=targeted\n", "0", "SELINUXTYPE=targeted\nSELINUX=permissive\n", "", false},
		"disabled til boot": {"enforcing", "SELINUX=disabled\n", "off", "SELINUX=enforcing\n", "", true},
	} {
		h := &host{config: ptr(c.config), enforce: c.enforce}
		reboot, err := ApplyMode(ctx, h, c.mode)
		if err != nil || reboot != c.reboot {
			t.Errorf("%s: reboot %v, %v", name, reboot, err)
			continue
		}
		if c.wantConfig == "" {
			c.wantConfig = c.config
		}
		if *h.config != c.wantConfig {
			t.Errorf("%s: config %q, want %q", name, *h.config, c.wantConfig)
		}
		var ran string
		for _, cmd := range h.ran {
			if strings.HasPrefix(cmd, "setenforce") {
				ran = cmd
			}
		}
		if ran != c.setenforce {
			t.Errorf("%s: ran %q, want %q", name, ran, c.setenforce)
		}
	}
}

func TestApplyModeErrors(t *testing.T) {
	h := &host{config: ptr("SELINUX=enforcing\n"), enforce: "1"}
	if _, err := ApplyMode(ctx, h, "disabled"); err == nil || len(h.ran) != 0 {
		t.Errorf("disabled reached the host: %v, %q", err, h.ran)
	}
	if _, err := ApplyMode(ctx, &host{}, "enforcing"); err == nil {
		t.Error("applied a mode with no config file")
	}
	h = &host{config: ptr("SELINUX=enforcing\n"), enforce: "1", out: map[string]ssh.Result{"setenforce": {ExitCode: 1, Stderr: []byte("setenforce: SELinux is disabled")}}}
	if _, err := ApplyMode(ctx, h, "permissive"); err == nil || err.Error() != "setenforce: SELinux is disabled" {
		t.Errorf("setenforce failing: %v", err)
	}
}

func TestBooleans(t *testing.T) {
	h := &host{out: map[string]ssh.Result{"/sys/fs/selinux/booleans/httpd_can_network_connect": {Stdout: []byte("1 1\n")}}}
	if on, err := ReadBoolean(ctx, h, "httpd_can_network_connect"); err != nil || !on {
		t.Errorf("read: %v, %v", on, err)
	}
	h.out = map[string]ssh.Result{"booleans": {Stdout: []byte("cat: No such file or directory\n")}}
	if _, err := ReadBoolean(ctx, h, "nope"); err == nil {
		t.Error("read garbage as a boolean")
	}
	for on, want := range map[bool]string{true: "setsebool -P httpd_can_network_connect on", false: "setsebool -P httpd_can_network_connect off"} {
		h := &host{}
		if err := ApplyBoolean(ctx, h, "httpd_can_network_connect", on); err != nil || !strings.HasSuffix(h.ran[0], "\n"+want) {
			t.Errorf("apply %v: %v, ran %q", on, err, h.ran)
		}
	}
	h = &host{}
	if err := ApplyBoolean(ctx, h, "x; reboot", true); err == nil || len(h.ran) != 0 {
		t.Errorf("an invalid name reached the host: %v, %q", err, h.ran)
	}
	// Every command first checks SELinux is on, and says so when it isn't.
	off := &host{out: map[string]ssh.Result{"test -d /sys/fs/selinux": {ExitCode: 1, Stderr: []byte("SELinux is not enabled on this host\n")}}}
	if _, err := ReadBoolean(ctx, off, "httpd_can_network_connect"); err == nil || err.Error() != "SELinux is not enabled on this host" {
		t.Errorf("read, disabled: %v", err)
	}
	if err := ApplyBoolean(ctx, off, "httpd_can_network_connect", true); err == nil || err.Error() != "SELinux is not enabled on this host" {
		t.Errorf("apply, disabled: %v", err)
	}
}

func TestFcontext(t *testing.T) {
	www := Fcontext{Target: "/srv/www(/.*)?", Type: "httpd_sys_content_t"}
	h := &host{out: map[string]ssh.Result{"semanage fcontext -l -C": {Stdout: []byte("/srv/www(/.*)?    all files    system_u:object_r:httpd_sys_content_t:s0\n")}}}
	if got, err := ReadFcontext(ctx, h, www); err != nil || got != "httpd_sys_content_t" {
		t.Errorf("read: %q, %v", got, err)
	}
	h = &host{}
	if err := ApplyFcontext(ctx, h, www); err != nil {
		t.Fatal(err)
	}
	// Add fails on a rule that's there, so modify is the fallback.
	for _, want := range []string{"semanage fcontext -a -t 'httpd_sys_content_t' '/srv/www(/.*)?' 2>/dev/null || semanage fcontext -m -t", "restorecon -R '/srv/www'"} {
		if !strings.Contains(h.ran[0], want) {
			t.Errorf("apply is missing %q:\n%s", want, h.ran[0])
		}
	}
	h = &host{}
	if err := DeleteFcontext(ctx, h, www); err != nil || !strings.Contains(h.ran[0], "semanage fcontext -d '/srv/www(/.*)?'") || !strings.Contains(h.ran[0], "restorecon -R '/srv/www'") {
		t.Errorf("delete: %v\n%s", err, h.ran)
	}
	// A rule for everything doesn't relabel the whole file system.
	root := Fcontext{Target: "/(.*)?", Type: "default_t"}
	for name, f := range map[string]func(modules.Runner) error{
		"apply":  func(r modules.Runner) error { return ApplyFcontext(ctx, r, root) },
		"delete": func(r modules.Runner) error { return DeleteFcontext(ctx, r, root) },
	} {
		h := &host{}
		if err := f(h); err != nil || strings.Contains(h.ran[0], "restorecon") {
			t.Errorf("%s: %v\n%s", name, err, h.ran)
		}
	}
	h = &host{}
	if err := ApplyFcontext(ctx, h, Fcontext{Target: "srv", Type: "httpd_sys_content_t"}); err == nil || len(h.ran) != 0 {
		t.Errorf("an invalid rule reached the host: %v, %q", err, h.ran)
	}
	missing := ssh.Result{ExitCode: 1, Stderr: []byte("semanage is not installed; add a package step for policycoreutils-python-utils first\n")}
	h = &host{out: map[string]ssh.Result{"semanage": missing}}
	if _, err := ReadFcontext(ctx, h, www); err == nil || !strings.HasPrefix(err.Error(), "semanage is not installed") {
		t.Errorf("read without semanage: %v", err)
	}
	gone := errors.New("connection lost")
	if err := DeleteFcontext(ctx, &lost{gone}, www); !errors.Is(err, gone) {
		t.Errorf("delete, runner error: %v", err)
	}
}

// lost fails every command with err.
type lost struct{ err error }

func (l *lost) Run(context.Context, string, []byte) (ssh.Result, error) { return ssh.Result{}, l.err }
