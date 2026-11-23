// Copyright (c) The Conn3x Authors
// SPDX-License-Identifier: MPL-2.0

// Package caps keeps a file's capabilities, with getcap and setcap.
package caps

import (
	"context"
	"errors"
	"fmt"
	"path"
	"regexp"
	"sort"
	"strings"

	"github.com/opentofu/opentofu/internal/conn3x/modules"
	"github.com/opentofu/opentofu/internal/conn3x/transport/ssh"
)

// Set is a file's capabilities, each name with its flags out of e, i and p,
// such as {"cap_net_raw": "ep"}.
type Set map[string]string

var (
	clause  = regexp.MustCompile(`^(cap_[a-z_]+(?:,cap_[a-z_]+)*)([=+])([eip]*)$`)
	capName = regexp.MustCompile(`^cap_[a-z_]+$`)
)

// Parse reads capabilities the way setcap takes them and getcap prints
// them: clauses such as "cap_net_raw+ep" or "cap_net_bind_service,cap_net_raw=ep",
// separated by spaces.
func Parse(text string) (Set, error) {
	s := Set{}
	for _, c := range strings.Fields(text) {
		m := clause.FindStringSubmatch(c)
		if m == nil {
			return nil, fmt.Errorf("%q isn't a capability such as cap_net_raw+ep: names start with cap_, then + or =, then any of e, i and p", c)
		}
		for _, name := range strings.Split(m[1], ",") {
			flags := m[3]
			if m[2] == "+" {
				flags += s[name]
			}
			s[name] = sortFlags(flags)
		}
	}
	for name, flags := range s {
		if flags == "" {
			delete(s, name)
		}
	}
	return s, nil
}

func sortFlags(f string) string {
	out := ""
	for _, c := range "eip" {
		if strings.ContainsRune(f, c) {
			out += string(c)
		}
	}
	return out
}

// String is s in setcap's form, sorted: "cap_net_bind_service,cap_net_raw=ep".
func (s Set) String() string {
	byFlags := map[string][]string{}
	for name, flags := range s {
		byFlags[flags] = append(byFlags[flags], name)
	}
	var clauses []string
	for flags, names := range byFlags {
		sort.Strings(names)
		clauses = append(clauses, strings.Join(names, ",")+"="+flags)
	}
	sort.Strings(clauses)
	return strings.Join(clauses, " ")
}

// Equal reports whether s and o grant the same.
func (s Set) Equal(o Set) bool { return s.String() == o.String() }

// File is a file and the capabilities it should have.
type File struct {
	Path string
	Caps Set
}

// Validate checks a File before anything reaches the host.
func (f File) Validate() error {
	if !path.IsAbs(f.Path) || strings.ContainsAny(f.Path, "\r\n") {
		return fmt.Errorf("path %q must be an absolute path", f.Path)
	}
	if len(f.Caps) == 0 {
		return errors.New("capabilities must name at least one; delete the step with on_remove = \"delete\" to take them all off")
	}
	for name := range f.Caps {
		if !capName.MatchString(name) {
			return fmt.Errorf("%q isn't a capability name", name)
		}
	}
	return nil
}

const missingHint = "setcap isn't on this host: install libcap2-bin on Debian and Ubuntu, or libcap on the Red Hat family, for example with a package step before this one"

// Read returns the capabilities the file has now, empty when it has none.
func Read(ctx context.Context, r modules.Runner, file string) (Set, error) {
	res, err := r.Run(ctx, "getcap -- "+ssh.Quote(file), nil)
	if err != nil {
		return nil, err
	}
	if res.ExitCode == 127 {
		return nil, errors.New(missingHint)
	}
	if res.ExitCode != 0 {
		return nil, fmt.Errorf("getcap %s: %s", file, strings.TrimSpace(string(res.Stderr)))
	}
	return parseGetcap(string(res.Stdout), file)
}

// parseGetcap reads getcap's line for file. Older libcap prints
// "/usr/bin/ping = cap_net_raw+ep", newer "/usr/bin/ping cap_net_raw=ep";
// a file without capabilities prints nothing.
func parseGetcap(out, file string) (Set, error) {
	for _, line := range strings.Split(out, "\n") {
		rest, ok := strings.CutPrefix(strings.TrimSpace(line), file+" ")
		if !ok {
			continue
		}
		return Parse(strings.TrimPrefix(strings.TrimSpace(rest), "= "))
	}
	return Set{}, nil
}

// Apply gives the file exactly f's capabilities.
func Apply(ctx context.Context, r modules.Runner, f File) error {
	if err := f.Validate(); err != nil {
		return err
	}
	return run(ctx, r, "setcap "+ssh.Quote(f.Caps.String())+" "+ssh.Quote(f.Path))
}

// Remove takes every capability off the file.
func Remove(ctx context.Context, r modules.Runner, file string) error {
	return run(ctx, r, "setcap -r "+ssh.Quote(file))
}

func run(ctx context.Context, r modules.Runner, cmd string) error {
	res, err := r.Run(ctx, cmd, nil)
	if err != nil {
		return err
	}
	if res.ExitCode == 127 {
		return errors.New(missingHint)
	}
	if res.ExitCode != 0 {
		return fmt.Errorf("%s: %s", strings.Fields(cmd)[0], strings.TrimSpace(string(res.Stderr)))
	}
	return nil
}
