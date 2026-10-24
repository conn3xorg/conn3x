// Copyright (c) The Conn3x Authors
// SPDX-License-Identifier: MPL-2.0

// Package selinux sets SELinux booleans and file context rules.
package selinux

import (
	"context"
	"errors"
	"fmt"
	"regexp"
	"strings"

	"github.com/opentofu/opentofu/internal/conn3x/modules"
	"github.com/opentofu/opentofu/internal/conn3x/transport/ssh"
)

var ident = regexp.MustCompile(`^[A-Za-z0-9_]+$`)

const enabled = `test -d /sys/fs/selinux || { echo "SELinux is not enabled on this host" >&2; exit 1; }`

// ValidateBoolean checks a boolean's name.
func ValidateBoolean(name string) error {
	if !ident.MatchString(name) {
		return fmt.Errorf("%q is not an SELinux boolean name", name)
	}
	return nil
}

// ReadBoolean returns a boolean's current value.
func ReadBoolean(ctx context.Context, r modules.Runner, name string) (bool, error) {
	res, err := r.Run(ctx, fmt.Sprintf("%s\ncat /sys/fs/selinux/booleans/%s", enabled, name), nil)
	if err := check(res, err); err != nil {
		return false, err
	}
	return parseBoolean(string(res.Stdout))
}

// parseBoolean reads the current value from a booleans file: "current pending".
func parseBoolean(s string) (bool, error) {
	f := strings.Fields(s)
	if len(f) == 0 || (f[0] != "0" && f[0] != "1") {
		return false, fmt.Errorf("unexpected boolean value %q", s)
	}
	return f[0] == "1", nil
}

// ApplyBoolean sets a boolean now and across reboots.
func ApplyBoolean(ctx context.Context, r modules.Runner, name string, on bool) error {
	if err := ValidateBoolean(name); err != nil {
		return err
	}
	v := "off"
	if on {
		v = "on"
	}
	res, err := r.Run(ctx, fmt.Sprintf("%s\nsetsebool -P %s %s", enabled, name, v), nil)
	return check(res, err)
}

// Fcontext is a local file context rule: files matching Target get Type.
type Fcontext struct {
	Target string // a path regular expression, such as /srv/www(/.*)?
	Type   string // such as httpd_sys_content_t
}

// Validate checks a rule before anything reaches the host.
func (f Fcontext) Validate() error {
	if !strings.HasPrefix(f.Target, "/") || strings.ContainsAny(f.Target, " \t\r\n") {
		return fmt.Errorf("target %q must be an absolute path expression without spaces", f.Target)
	}
	if !ident.MatchString(f.Type) {
		return fmt.Errorf("setype %q is not an SELinux type", f.Type)
	}
	return nil
}

// RestorePath is the literal directory in front of Target's first regular
// expression character: what restorecon relabels after a change. It is ""
// when that would be the whole file system.
func (f Fcontext) RestorePath() string {
	p := f.Target
	if i := strings.IndexAny(p, `([*?+^$|{\`); i >= 0 {
		p = p[:i]
		// A group, as in /srv/www(/.*)?, follows a whole name; anything
		// else, as in /srv/www.*, may cut one short, so use its parent.
		if f.Target[i] != '(' && !strings.HasSuffix(p, "/") {
			p = p[:max(strings.LastIndex(p, "/"), 0)]
		}
	}
	return strings.TrimRight(p, "/")
}

const semanage = `command -v semanage >/dev/null || { echo "semanage is not installed; add a package step for policycoreutils-python-utils first" >&2; exit 1; }`

// ReadFcontext returns the type a local rule gives Target, or "" if no local
// rule exists for it.
func ReadFcontext(ctx context.Context, r modules.Runner, f Fcontext) (string, error) {
	res, err := r.Run(ctx, fmt.Sprintf("%s\n%s\nsemanage fcontext -l -C", enabled, semanage), nil)
	if err := check(res, err); err != nil {
		return "", err
	}
	return localType(string(res.Stdout), f.Target), nil
}

// localType finds target's type in "semanage fcontext -l -C" output.
func localType(out, target string) string {
	for _, line := range strings.Split(out, "\n") {
		fields := strings.Fields(line)
		if len(fields) < 2 || fields[0] != target {
			continue
		}
		if parts := strings.Split(fields[len(fields)-1], ":"); len(parts) >= 3 {
			return parts[2]
		}
	}
	return ""
}

// ApplyFcontext adds or changes the rule, then relabels what it covers.
func ApplyFcontext(ctx context.Context, r modules.Runner, f Fcontext) error {
	if err := f.Validate(); err != nil {
		return err
	}
	t, ty := ssh.Quote(f.Target), ssh.Quote(f.Type)
	script := fmt.Sprintf("%s\n%s\nsemanage fcontext -a -t %s %s 2>/dev/null || semanage fcontext -m -t %s %s", enabled, semanage, ty, t, ty, t)
	if p := f.RestorePath(); p != "" {
		script += fmt.Sprintf("\nif [ -e %[1]s ]; then restorecon -R %[1]s; fi", ssh.Quote(p))
	}
	res, err := r.Run(ctx, script, nil)
	return check(res, err)
}

// DeleteFcontext removes the local rule and relabels what it covered.
func DeleteFcontext(ctx context.Context, r modules.Runner, f Fcontext) error {
	script := fmt.Sprintf("%s\n%s\nsemanage fcontext -d %s", enabled, semanage, ssh.Quote(f.Target))
	if p := f.RestorePath(); p != "" {
		script += fmt.Sprintf("\nif [ -e %[1]s ]; then restorecon -R %[1]s; fi", ssh.Quote(p))
	}
	res, err := r.Run(ctx, script, nil)
	return check(res, err)
}

func check(res ssh.Result, err error) error {
	if err != nil {
		return err
	}
	if res.ExitCode != 0 {
		return errors.New(strings.TrimSpace(string(res.Stderr) + string(res.Stdout)))
	}
	return nil
}
