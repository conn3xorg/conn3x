// Copyright (c) The Conn3x Authors
// SPDX-License-Identifier: MPL-2.0

package windows

import (
	"context"
	"encoding/json"
	"fmt"
	"regexp"
	"strings"
	"time"

	"github.com/opentofu/opentofu/internal/conn3x/modules/windows/ps"
)

var optionalFeatureName = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$`)

// OptionalFeature is a Windows optional feature, as DISM names it, such as
// TelnetClient or Microsoft-Windows-Subsystem-Linux.
type OptionalFeature struct {
	Name   string
	Absent bool
	// IncludeParent also enables the features this one sits under (-All).
	IncludeParent bool
	// Source is where DISM finds the feature's files when Windows doesn't
	// have them, such as D:\sources\sxs.
	Source string
}

// Validate checks an optional feature before anything runs.
func (f OptionalFeature) Validate() error {
	if !optionalFeatureName.MatchString(f.Name) {
		return fmt.Errorf("optional feature %q is not a feature name, such as TelnetClient", f.Name)
	}
	if strings.ContainsFunc(f.Source, func(r rune) bool { return r < ' ' }) {
		return fmt.Errorf("source %q has a control character", f.Source)
	}
	return nil
}

// OptionalFeatureInSync reads an optional feature. A change waiting for a
// reboot counts as made, so the plan after it is clean, and pending says
// it's waiting.
func OptionalFeatureInSync(ctx context.Context, r ps.Runner, f OptionalFeature) (inSync, pending bool, err error) {
	res, err := ps.Read(ctx, r, script("read_optional_feature.ps1"), map[string]any{"name": f.Name})
	if err != nil {
		return false, false, err
	}
	var a struct {
		Exists bool   `json:"exists"`
		State  string `json:"state"`
	}
	if err := json.Unmarshal(res.Value, &a); err != nil {
		return false, false, fmt.Errorf("reading optional feature %s: %w", f.Name, err)
	}
	if !a.Exists {
		return false, false, fmt.Errorf("Windows has no optional feature named %s here", f.Name)
	}
	pending = strings.HasSuffix(a.State, "Pending")
	if f.Absent {
		return a.State == "Disabled" || a.State == "DisablePending" || a.State == "DisabledWithPayloadRemoved", pending, nil
	}
	return a.State == "Enabled" || a.State == "EnablePending", pending, nil
}

// ApplyOptionalFeature enables or disables it, never restarting, and says
// whether Windows wants a reboot.
func ApplyOptionalFeature(ctx context.Context, r ps.Runner, f OptionalFeature, timeout time.Duration) (restart bool, err error) {
	res, err := ps.Apply(ctx, r, script("apply_optional_feature.ps1"), map[string]any{
		"name": f.Name, "present": !f.Absent, "include_parent": f.IncludeParent && !f.Absent, "source": f.Source,
	}, timeout)
	if err != nil {
		return false, err
	}
	var a struct {
		Restart bool `json:"restart"`
	}
	if err := json.Unmarshal(res.Value, &a); err != nil {
		return false, fmt.Errorf("reading the result for optional feature %s: %w", f.Name, err)
	}
	return a.Restart, nil
}
