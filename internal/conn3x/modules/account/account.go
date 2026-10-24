// Copyright (c) The Conn3x Authors
// SPDX-License-Identifier: MPL-2.0

// Package account manages local users and groups with the shadow-utils
// commands, which keep /etc/shadow and SELinux labels right.
package account

import (
	"context"
	"fmt"
	"path"
	"regexp"
	"slices"
	"strconv"
	"strings"

	"github.com/opentofu/opentofu/internal/conn3x/modules"
	"github.com/opentofu/opentofu/internal/conn3x/transport/ssh"
)

var namePattern = regexp.MustCompile(`^[a-z_][a-z0-9_-]{0,31}$`)

// UserSpec is a user as it should be. Nil fields are left as they are.
type UserSpec struct {
	Name   string
	UID    *int
	Group  *string   // primary group
	Groups *[]string // supplementary groups, the complete list
	Home   *string
	Shell  *string
	System bool // only used when creating
}

// User is a user as it is.
type User struct {
	Exists bool
	UID    int
	Group  string
	Groups []string
	Home   string
	Shell  string
}

// Validate checks a UserSpec before anything runs on a host.
func (s UserSpec) Validate() error {
	if !namePattern.MatchString(s.Name) {
		return fmt.Errorf("user name %q is not valid: use lowercase letters, digits, - and _, starting with a letter or _", s.Name)
	}
	if s.Group != nil && !namePattern.MatchString(*s.Group) {
		return fmt.Errorf("group name %q is not valid", *s.Group)
	}
	if s.Groups != nil {
		for _, g := range *s.Groups {
			if !namePattern.MatchString(g) {
				return fmt.Errorf("group name %q is not valid", g)
			}
		}
	}
	for label, p := range map[string]*string{"home": s.Home, "shell": s.Shell} {
		if p != nil && !path.IsAbs(*p) {
			return fmt.Errorf("%s %q must be an absolute path", label, *p)
		}
	}
	if s.UID != nil && *s.UID < 0 {
		return fmt.Errorf("uid must not be negative")
	}
	return nil
}

// ReadUser reports the user's current state.
func ReadUser(ctx context.Context, r modules.Runner, name string) (User, error) {
	if !namePattern.MatchString(name) {
		return User{}, fmt.Errorf("user name %q is not valid", name)
	}
	q := ssh.Quote(name)
	res, err := r.Run(ctx, "getent passwd -- "+q, nil)
	if err != nil {
		return User{}, err
	}
	if res.ExitCode == 2 {
		return User{}, nil
	}
	if res.ExitCode != 0 {
		return User{}, fmt.Errorf("getent passwd %s: %s", name, strings.TrimSpace(string(res.Stderr)))
	}
	fields := strings.Split(strings.TrimSpace(string(res.Stdout)), ":")
	if len(fields) != 7 {
		return User{}, fmt.Errorf("getent passwd %s: unexpected output %q", name, res.Stdout)
	}
	uid, _ := strconv.Atoi(fields[2])
	u := User{Exists: true, UID: uid, Home: fields[5], Shell: fields[6]}

	gres, err := r.Run(ctx, "getent group -- "+ssh.Quote(fields[3]), nil)
	if err != nil {
		return User{}, err
	}
	u.Group = fields[3]
	if gres.ExitCode == 0 {
		if g := strings.Split(strings.TrimSpace(string(gres.Stdout)), ":"); len(g) >= 1 && g[0] != "" {
			u.Group = g[0]
		}
	}

	ires, err := r.Run(ctx, "id -Gn -- "+q, nil)
	if err != nil {
		return User{}, err
	}
	for _, g := range strings.Fields(string(ires.Stdout)) {
		if g != u.Group {
			u.Groups = append(u.Groups, g)
		}
	}
	slices.Sort(u.Groups)
	return u, nil
}

// UserNeedsChange reports whether ApplyUser would change anything.
func UserNeedsChange(s UserSpec, u User) bool {
	if !u.Exists {
		return true
	}
	if s.UID != nil && *s.UID != u.UID ||
		s.Group != nil && *s.Group != u.Group ||
		s.Home != nil && *s.Home != u.Home ||
		s.Shell != nil && *s.Shell != u.Shell {
		return true
	}
	if s.Groups != nil {
		want := slices.Clone(*s.Groups)
		slices.Sort(want)
		want = slices.Compact(want)
		return !slices.Equal(want, u.Groups)
	}
	return false
}

// ApplyUser creates the user, or changes it to match.
func ApplyUser(ctx context.Context, r modules.Runner, s UserSpec) error {
	if err := s.Validate(); err != nil {
		return err
	}
	u, err := ReadUser(ctx, r, s.Name)
	if err != nil {
		return err
	}
	var args []string
	if s.UID != nil {
		args = append(args, "-u", strconv.Itoa(*s.UID))
	}
	if s.Group != nil {
		args = append(args, "-g", ssh.Quote(*s.Group))
	}
	if s.Groups != nil {
		args = append(args, "-G", ssh.Quote(strings.Join(*s.Groups, ",")))
	}
	if s.Home != nil {
		args = append(args, "-d", ssh.Quote(*s.Home))
	}
	if s.Shell != nil {
		args = append(args, "-s", ssh.Quote(*s.Shell))
	}
	if !u.Exists {
		cmd := append([]string{"useradd", "-m"}, args...)
		if s.System {
			cmd = append(cmd, "-r")
		}
		return run(ctx, r, strings.Join(append(cmd, "--", ssh.Quote(s.Name)), " "))
	}
	if !UserNeedsChange(s, u) {
		return nil
	}
	return run(ctx, r, strings.Join(append(append([]string{"usermod"}, args...), "--", ssh.Quote(s.Name)), " "))
}

// DeleteUser removes the user and keeps its home directory.
func DeleteUser(ctx context.Context, r modules.Runner, name string) error {
	u, err := ReadUser(ctx, r, name)
	if err != nil || !u.Exists {
		return err
	}
	return run(ctx, r, "userdel -- "+ssh.Quote(name))
}

// GroupSpec is a group as it should be.
type GroupSpec struct {
	Name   string
	GID    *int
	System bool // only used when creating
}

// Group is a group as it is.
type Group struct {
	Exists bool
	GID    int
}

// Validate checks a GroupSpec before anything runs on a host.
func (s GroupSpec) Validate() error {
	if !namePattern.MatchString(s.Name) {
		return fmt.Errorf("group name %q is not valid", s.Name)
	}
	if s.GID != nil && *s.GID < 0 {
		return fmt.Errorf("gid must not be negative")
	}
	return nil
}

// ReadGroup reports the group's current state.
func ReadGroup(ctx context.Context, r modules.Runner, name string) (Group, error) {
	if !namePattern.MatchString(name) {
		return Group{}, fmt.Errorf("group name %q is not valid", name)
	}
	res, err := r.Run(ctx, "getent group -- "+ssh.Quote(name), nil)
	if err != nil {
		return Group{}, err
	}
	if res.ExitCode == 2 {
		return Group{}, nil
	}
	if res.ExitCode != 0 {
		return Group{}, fmt.Errorf("getent group %s: %s", name, strings.TrimSpace(string(res.Stderr)))
	}
	fields := strings.Split(strings.TrimSpace(string(res.Stdout)), ":")
	if len(fields) < 3 {
		return Group{}, fmt.Errorf("getent group %s: unexpected output %q", name, res.Stdout)
	}
	gid, _ := strconv.Atoi(fields[2])
	return Group{Exists: true, GID: gid}, nil
}

// GroupNeedsChange reports whether ApplyGroup would change anything.
func GroupNeedsChange(s GroupSpec, g Group) bool {
	return !g.Exists || s.GID != nil && *s.GID != g.GID
}

// ApplyGroup creates the group, or changes its gid to match.
func ApplyGroup(ctx context.Context, r modules.Runner, s GroupSpec) error {
	if err := s.Validate(); err != nil {
		return err
	}
	g, err := ReadGroup(ctx, r, s.Name)
	if err != nil {
		return err
	}
	var args []string
	if s.GID != nil {
		args = append(args, "-g", strconv.Itoa(*s.GID))
	}
	if !g.Exists {
		if s.System {
			args = append(args, "-r")
		}
		return run(ctx, r, strings.Join(append(append([]string{"groupadd"}, args...), "--", ssh.Quote(s.Name)), " "))
	}
	if !GroupNeedsChange(s, g) {
		return nil
	}
	return run(ctx, r, strings.Join(append(append([]string{"groupmod"}, args...), "--", ssh.Quote(s.Name)), " "))
}

// DeleteGroup removes the group.
func DeleteGroup(ctx context.Context, r modules.Runner, name string) error {
	g, err := ReadGroup(ctx, r, name)
	if err != nil || !g.Exists {
		return err
	}
	return run(ctx, r, "groupdel -- "+ssh.Quote(name))
}

func run(ctx context.Context, r modules.Runner, cmd string) error {
	res, err := r.Run(ctx, cmd, nil)
	if err != nil {
		return err
	}
	if res.ExitCode != 0 {
		msg := strings.TrimSpace(string(res.Stderr))
		if msg == "" {
			msg = fmt.Sprintf("exit status %d", res.ExitCode)
		}
		return fmt.Errorf("%s: %s", strings.Fields(cmd)[0], msg)
	}
	return nil
}
