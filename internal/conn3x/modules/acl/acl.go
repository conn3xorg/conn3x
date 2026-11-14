// Copyright (c) The Conn3x Authors
// SPDX-License-Identifier: MPL-2.0

// Package acl keeps one POSIX ACL entry on a path, with getfacl and setfacl.
package acl

import (
	"context"
	"errors"
	"fmt"
	"path"
	"regexp"
	"strings"

	"github.com/opentofu/opentofu/internal/conn3x/modules"
	"github.com/opentofu/opentofu/internal/conn3x/transport/ssh"
)

// Entry is one ACL entry as it should be.
type Entry struct {
	Path        string
	Type        string // user, group, mask or other
	Entity      string // the user or group, for those types
	Permissions string // any of r, w and x, in any order; "" is none
	Default     bool   // the directory's default ACL, which new files inherit
	Absent      bool   // the entry should not be there
}

var entityPattern = regexp.MustCompile(`^[A-Za-z0-9_.][A-Za-z0-9_.@-]*$`)

// Validate checks an Entry before anything reaches the host.
func (e Entry) Validate() error {
	switch {
	case !path.IsAbs(e.Path) || strings.ContainsAny(e.Path, "\r\n"):
		return fmt.Errorf("path %q must be an absolute path", e.Path)
	case e.Type != "user" && e.Type != "group" && e.Type != "mask" && e.Type != "other":
		return fmt.Errorf(`etype must be "user", "group", "mask" or "other", not %q`, e.Type)
	case (e.Type == "user" || e.Type == "group") && !entityPattern.MatchString(e.Entity):
		return fmt.Errorf("entity %q must name the %s, by name or number", e.Entity, e.Type)
	case (e.Type == "mask" || e.Type == "other") && e.Entity != "":
		return fmt.Errorf("a %s entry has no entity", e.Type)
	case e.Absent && (e.Type == "mask" || e.Type == "other") && !e.Default:
		return fmt.Errorf("a path always has a %s entry, so it can't be absent; set its permissions instead", e.Type)
	}
	if strings.Trim(e.Permissions, "rwx") != "" {
		return fmt.Errorf("permissions %q may only hold r, w and x", e.Permissions)
	}
	return nil
}

// key is the entry as getfacl names it, without its permissions.
func (e Entry) key() string {
	k := e.Type + ":" + e.Entity
	if e.Default {
		k = "default:" + k
	}
	return k
}

// perms is the permissions in getfacl's form, such as r-x.
func (e Entry) perms() string {
	out := []byte("---")
	for i, c := range "rwx" {
		if strings.ContainsRune(e.Permissions, c) {
			out[i] = byte(c)
		}
	}
	return string(out)
}

const missingHint = "setfacl isn't on this host: install the acl package, for example with a package step before this one"

// Read returns the entry's permissions on the host in getfacl's form, and
// whether it's there at all.
func Read(ctx context.Context, r modules.Runner, e Entry) (perms string, ok bool, err error) {
	res, err := r.Run(ctx, "getfacl --omit-header --absolute-names --no-effective -- "+ssh.Quote(e.Path), nil)
	if err != nil {
		return "", false, err
	}
	if res.ExitCode == 127 {
		return "", false, errors.New(missingHint)
	}
	if res.ExitCode != 0 {
		return "", false, fmt.Errorf("getfacl %s: %s", e.Path, strings.TrimSpace(string(res.Stderr)))
	}
	return find(string(res.Stdout), e.key())
}

func find(out, key string) (string, bool, error) {
	for _, line := range strings.Split(out, "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		i := strings.LastIndex(line, ":")
		if i < 0 {
			continue
		}
		if line[:i] == key {
			return line[i+1:], true, nil
		}
	}
	return "", false, nil
}

// Matches reports whether what Read found is what the entry wants.
func (e Entry) Matches(perms string, ok bool) bool {
	if e.Absent {
		return !ok
	}
	return ok && perms == e.perms()
}

// Apply sets or removes the entry.
func Apply(ctx context.Context, r modules.Runner, e Entry) error {
	if err := e.Validate(); err != nil {
		return err
	}
	spec := e.key()
	cmd := "setfacl -x "
	if !e.Absent {
		cmd, spec = "setfacl -m ", spec+":"+e.perms()
	}
	res, err := r.Run(ctx, cmd+ssh.Quote(spec)+" -- "+ssh.Quote(e.Path), nil)
	if err != nil {
		return err
	}
	if res.ExitCode == 127 {
		return errors.New(missingHint)
	}
	if res.ExitCode != 0 {
		return fmt.Errorf("setfacl %s: %s", e.Path, strings.TrimSpace(string(res.Stderr)))
	}
	return nil
}
