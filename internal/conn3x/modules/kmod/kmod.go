// Copyright (c) The Conn3x Authors
// SPDX-License-Identifier: MPL-2.0

// Package kmod loads a kernel module, with its parameters, and keeps it
// loaded across reboots through /etc/modules-load.d and /etc/modprobe.d.
package kmod

import (
	"context"
	"errors"
	"fmt"
	"regexp"
	"strings"

	"github.com/opentofu/opentofu/internal/conn3x/modules"
	"github.com/opentofu/opentofu/internal/conn3x/modules/file"
	"github.com/opentofu/opentofu/internal/conn3x/transport/ssh"
)

// Module is one kernel module.
type Module struct {
	Name   string
	Params []string // key=value
	Absent bool     // unload it, and keep it from loading at boot
	// Persistent manages the boot files: modules-load.d to load it, and
	// modprobe.d for its parameters. Without it, they're left alone.
	Persistent bool
}

var (
	nameRe  = regexp.MustCompile(`^[A-Za-z0-9_-]{1,64}$`)
	paramRe = regexp.MustCompile(`^([A-Za-z0-9_]{1,64})=([A-Za-z0-9_.,:/+-]{0,256})$`)
)

// kernelName is the name /proc/modules and /sys/module use: the kernel
// treats - and _ in module names as the same, and shows _.
func (m Module) kernelName() string { return strings.ReplaceAll(m.Name, "-", "_") }

// LoadPath and OptionsPath are the boot files.
func (m Module) LoadPath() string    { return "/etc/modules-load.d/" + m.Name + ".conf" }
func (m Module) OptionsPath() string { return "/etc/modprobe.d/" + m.Name + ".conf" }

// Validate checks a Module before anything reaches the host.
func (m Module) Validate() error {
	if !nameRe.MatchString(m.Name) {
		return fmt.Errorf("name %q must be a kernel module name: letters, digits, _ and -", m.Name)
	}
	seen := map[string]bool{}
	for _, p := range m.Params {
		g := paramRe.FindStringSubmatch(p)
		if g == nil {
			return fmt.Errorf("params %q must be key=value, with a value of letters, digits and _ . , : / + -", p)
		}
		if seen[g[1]] {
			return fmt.Errorf("params sets %s twice", g[1])
		}
		seen[g[1]] = true
	}
	if m.Absent && len(m.Params) > 0 {
		return fmt.Errorf("params don't apply to a module that's absent")
	}
	return nil
}

func (m Module) loadContent() string {
	return "# Written by Conn3x.\n" + m.Name + "\n"
}

func (m Module) optionsContent() string {
	return "# Written by Conn3x.\noptions " + m.Name + " " + strings.Join(m.Params, " ") + "\n"
}

// Actual is what the host has.
type Actual struct {
	Loaded bool
	// Params holds the live value of each param in m.Params that the
	// module shows in /sys/module; one declared without that isn't there.
	Params      map[string]string
	LoadFile    string // "" when missing
	OptionsFile string
}

// Read reads /proc/modules, the live parameters and the boot files.
func Read(ctx context.Context, r modules.Runner, m Module) (Actual, error) {
	if err := m.Validate(); err != nil {
		return Actual{}, err
	}
	k := ssh.Quote(m.kernelName())
	script := "if grep -q \"^\"" + k + "\" \" /proc/modules; then echo loaded; fi\n"
	for _, p := range m.Params {
		key := strings.SplitN(p, "=", 2)[0]
		f := "/sys/module/" + m.kernelName() + "/parameters/" + key
		script += "if [ -r " + f + " ]; then printf 'param %s %s\\n' " + ssh.Quote(key) + " \"$(cat " + f + ")\"; fi\n"
	}
	res, err := r.Run(ctx, script, nil)
	if err != nil {
		return Actual{}, err
	}
	if res.ExitCode != 0 {
		return Actual{}, errors.New(strings.TrimSpace(string(res.Stderr)))
	}
	a := Actual{Params: map[string]string{}}
	for _, line := range strings.Split(string(res.Stdout), "\n") {
		switch f := strings.SplitN(line, " ", 3); {
		case line == "loaded":
			a.Loaded = true
		case len(f) >= 2 && f[0] == "param":
			v := ""
			if len(f) == 3 {
				v = f[2]
			}
			a.Params[f[1]] = v
		}
	}
	for path, out := range map[string]*string{m.LoadPath(): &a.LoadFile, m.OptionsPath(): &a.OptionsFile} {
		f, err := file.Read(ctx, r, path)
		if err != nil {
			return Actual{}, err
		}
		if f.Exists {
			*out = f.Content
		}
	}
	return a, nil
}

// sameParam compares a live value with a wanted one: the kernel shows a
// bool parameter as Y or N, whatever it was given as.
func sameParam(live, want string) bool {
	norm := func(s string) string {
		switch strings.ToLower(s) {
		case "y", "1", "yes", "true", "on":
			return "Y"
		case "n", "0", "no", "false", "off":
			return "N"
		}
		return s
	}
	return live == want || norm(live) == norm(want)
}

// paramsMatch compares the params the kernel shows. One it doesn't can't
// be read back; with persistent, the options file stands in for it.
func (m Module) paramsMatch(a Actual) bool {
	for _, p := range m.Params {
		k, v, _ := strings.Cut(p, "=")
		if live, ok := a.Params[k]; ok && !sameParam(live, v) {
			return false
		}
	}
	return true
}

func (m Module) wantOptions() string {
	if len(m.Params) == 0 {
		return ""
	}
	return m.optionsContent()
}

// InSync reports whether the module is loaded, or not, as m says, with its
// parameters and boot files.
func (m Module) InSync(a Actual) bool {
	if m.Absent {
		return !a.Loaded && (!m.Persistent || a.LoadFile == "" && a.OptionsFile == "")
	}
	if !a.Loaded || !m.paramsMatch(a) {
		return false
	}
	if !m.Persistent {
		return true
	}
	return a.LoadFile == m.loadContent() && a.OptionsFile == m.wantOptions()
}

// Apply loads or unloads the module and writes or removes its boot files.
// A module loaded with other parameters is unloaded and loaded again, which
// fails while something uses it.
func Apply(ctx context.Context, r modules.Runner, m Module) error {
	if err := m.Validate(); err != nil {
		return err
	}
	a, err := Read(ctx, r, m)
	if err != nil {
		return err
	}
	if m.Persistent {
		if err := m.writeBootFiles(ctx, r); err != nil {
			return err
		}
	}
	name := ssh.Quote(m.Name)
	var script string
	switch {
	case m.Absent && a.Loaded:
		script = "modprobe -r -- " + name
	case m.Absent:
	// New params need a reload, including ones the kernel doesn't show,
	// which only the options file says have changed.
	case a.Loaded && (!m.paramsMatch(a) || m.Persistent && a.OptionsFile != m.wantOptions()):
		script = "modprobe -r -- " + name + " && modprobe -- " + name + " " + quoteAll(m.Params)
	case !a.Loaded:
		script = "modprobe -- " + name + " " + quoteAll(m.Params)
	}
	if script != "" {
		res, err := r.Run(ctx, modules.GuardRoot(script), nil)
		if err != nil {
			return err
		}
		if res.ExitCode != 0 {
			return fmt.Errorf("modprobe %s: %s", m.Name, strings.TrimSpace(string(res.Stderr)+string(res.Stdout)))
		}
	}
	after, err := Read(ctx, r, m)
	if err != nil {
		return err
	}
	if !m.InSync(after) {
		if !m.Absent && after.Loaded {
			return fmt.Errorf("%s loaded, but its parameters didn't take; /sys/module/%s/parameters has what the kernel kept", m.Name, m.kernelName())
		}
		return fmt.Errorf("%s isn't %s after the change", m.Name, map[bool]string{true: "unloaded", false: "loaded"}[m.Absent])
	}
	return nil
}

func (m Module) writeBootFiles(ctx context.Context, r modules.Runner) error {
	if m.Absent {
		for _, p := range []string{m.LoadPath(), m.OptionsPath()} {
			if err := file.Delete(ctx, r, p); err != nil {
				return err
			}
		}
		return nil
	}
	if err := file.Apply(ctx, r, file.Desired{Path: m.LoadPath(), Content: m.loadContent(), Mode: "0644", Owner: "root", Group: "root"}); err != nil {
		return err
	}
	if len(m.Params) == 0 {
		return file.Delete(ctx, r, m.OptionsPath())
	}
	return file.Apply(ctx, r, file.Desired{Path: m.OptionsPath(), Content: m.optionsContent(), Mode: "0644", Owner: "root", Group: "root"})
}

func quoteAll(words []string) string {
	q := make([]string, len(words))
	for i, w := range words {
		q[i] = ssh.Quote(w)
	}
	return strings.Join(q, " ")
}
