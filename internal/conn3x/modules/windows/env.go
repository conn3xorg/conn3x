// Copyright (c) The Conn3x Authors
// SPDX-License-Identifier: MPL-2.0

package windows

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/opentofu/opentofu/internal/conn3x/modules/windows/ps"
)

// The registry keys Windows keeps environment variables in: the machine's,
// and the login user's own.
const (
	machineEnvKey = `SYSTEM\CurrentControlSet\Control\Session Manager\Environment`
	userEnvKey    = `Environment`
)

func envKey(user bool) string {
	if user {
		return userEnvKey
	}
	return machineEnvKey
}

// EnvVar is one environment variable, the machine's or the login user's.
type EnvVar struct {
	Name, Value string
	User        bool // the login user's, in HKCU, rather than the machine's
	Absent      bool
}

// Validate checks a variable before anything reaches the host.
func (e EnvVar) Validate() error {
	if e.Name == "" || strings.ContainsAny(e.Name, "=") || strings.ContainsFunc(e.Name, func(r rune) bool { return r < 0x20 }) || len(e.Name) > 255 {
		return fmt.Errorf("name %q must be a variable name: no =, no control characters, at most 255", e.Name)
	}
	if strings.ContainsRune(e.Value, 0) {
		return errors.New("value must not hold a NUL")
	}
	return nil
}

// ActualEnv is a variable as the registry holds it, unexpanded.
type ActualEnv struct {
	Exists      bool
	Value, Kind string // Kind as .NET names it: String, ExpandString, ...
}

// ReadEnv reads a variable from the registry, without expanding %names%.
func ReadEnv(ctx context.Context, r ps.Runner, name string, user bool) (ActualEnv, error) {
	res, err := ps.Read(ctx, r, script("read_env.ps1"), map[string]any{"key": envKey(user), "name": name, "user": user})
	if err != nil {
		return ActualEnv{}, err
	}
	var a ActualEnv
	var raw struct {
		Exists bool   `json:"exists"`
		Kind   string `json:"kind"`
		Value  string `json:"value"`
	}
	if err := json.Unmarshal(res.Value, &raw); err != nil {
		return ActualEnv{}, errors.New("reading an environment variable: the host's answer wasn't valid")
	}
	a.Exists, a.Kind, a.Value = raw.Exists, raw.Kind, raw.Value
	return a, nil
}

// Matches reports whether the host has the variable as configured.
func (e EnvVar) Matches(a ActualEnv) bool {
	if e.Absent {
		return !a.Exists
	}
	return a.Exists && a.Value == e.Value
}

// ApplyEnv sets or removes the variable. A new value stays a String, or an
// ExpandString when it holds %; an existing one keeps its kind.
func ApplyEnv(ctx context.Context, r ps.Runner, e EnvVar) error {
	if err := e.Validate(); err != nil {
		return err
	}
	_, err := ps.Apply(ctx, r, script("apply_env.ps1"), map[string]any{"key": envKey(e.User), "name": e.Name, "value": e.Value, "user": e.User, "absent": e.Absent}, time.Minute)
	return err
}

// ErrPathVariable is windows_environment refusing Path: it's one string of
// folders, and a value set whole would drop whatever else is in it.
var ErrPathVariable = errors.New(`name Path is the list of folders Windows searches; give each folder its own windows_path step, so the others stay as they are`)

// PathEntry is one folder in the machine's or the login user's Path.
type PathEntry struct {
	Element string
	User    bool
	Absent  bool
}

// Validate checks an element before anything reaches the host.
func (p PathEntry) Validate() error {
	if strings.TrimSpace(p.Element) == "" || strings.ContainsAny(p.Element, `;"`) || strings.ContainsFunc(p.Element, func(r rune) bool { return r < 0x20 }) {
		return fmt.Errorf("element %q must be one folder: not empty, and no ; or \" or control characters", p.Element)
	}
	return nil
}

// sameElement compares folders the way Windows does: without case, and
// with or without a trailing backslash.
func sameElement(a, b string) bool {
	return strings.EqualFold(strings.TrimRight(strings.TrimSpace(a), `\`), strings.TrimRight(strings.TrimSpace(b), `\`))
}

func (p PathEntry) present(path string) bool {
	for _, e := range strings.Split(path, ";") {
		if sameElement(e, p.Element) {
			return true
		}
	}
	return false
}

// Matches reports whether Path has the element, or doesn't for Absent.
func (p PathEntry) Matches(a ActualEnv) bool { return p.present(a.Value) == !p.Absent }

// NewPath is path with the element added at the end, or every copy of it
// taken out; the other elements and their order stay as they are.
func (p PathEntry) NewPath(path string) string {
	if !p.Absent {
		if p.present(path) {
			return path
		}
		if strings.TrimRight(path, ";") == "" {
			return p.Element
		}
		return strings.TrimRight(path, ";") + ";" + p.Element
	}
	var keep []string
	for _, e := range strings.Split(path, ";") {
		if !sameElement(e, p.Element) {
			keep = append(keep, e)
		}
	}
	return strings.Join(keep, ";")
}

// ApplyPath adds or removes the element, reading Path just before writing
// it back.
func ApplyPath(ctx context.Context, r ps.Runner, p PathEntry) error {
	if err := p.Validate(); err != nil {
		return err
	}
	a, err := ReadEnv(ctx, r, "Path", p.User)
	if err != nil {
		return err
	}
	if p.Matches(a) {
		return nil
	}
	return ApplyEnv(ctx, r, EnvVar{Name: "Path", Value: p.NewPath(a.Value), User: p.User})
}
