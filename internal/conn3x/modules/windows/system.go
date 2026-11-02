// Copyright (c) The Conn3x Authors
// SPDX-License-Identifier: MPL-2.0

package windows

import (
	"context"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/opentofu/opentofu/internal/conn3x/modules/windows/ps"
)

// Registry value types, by the name .NET's RegistryValueKind gives them.
var registryKinds = map[string]string{
	"string":        "String",
	"expand_string": "ExpandString",
	"multi_string":  "MultiString",
	"dword":         "DWord",
	"qword":         "QWord",
	"binary":        "Binary",
}

// RegistryValue is one value under HKLM.
type RegistryValue struct {
	Key  string // under HKLM, as written with the hive: HKLM\SOFTWARE\App
	Name string // empty is the key's default value
	Type string // one of registryKinds
	Data string // numbers in decimal, binary in hex, multi_string one per line
}

var registryKey = regexp.MustCompile(`(?i)^(HKLM|HKEY_LOCAL_MACHINE)\\([^\x00-\x1f*?]+)$`)

// subKey is the part of Key below the hive.
func (v RegistryValue) subKey() (string, error) {
	m := registryKey.FindStringSubmatch(v.Key)
	if m == nil {
		return "", fmt.Errorf(`key %q must be under HKLM, such as HKLM\SOFTWARE\App`, v.Key)
	}
	for _, part := range strings.Split(m[2], `\`) {
		if part == "" || part == "." || part == ".." {
			return "", fmt.Errorf("key %q has an empty or relative part", v.Key)
		}
	}
	return m[2], nil
}

// Validate checks everything but the data, whose errors must not quote it.
func (v RegistryValue) Validate() error {
	if _, err := v.subKey(); err != nil {
		return err
	}
	if strings.ContainsFunc(v.Name, func(r rune) bool { return r < 0x20 }) || len(v.Name) > 16383 {
		return fmt.Errorf("value name %q isn't valid", v.Name)
	}
	if _, ok := registryKinds[v.Type]; !ok {
		return fmt.Errorf(`type %q must be "string", "expand_string", "multi_string", "dword", "qword" or "binary"`, v.Type)
	}
	return nil
}

// canonical turns data as configured into one form to compare and hash. Its
// errors never quote the data, which may be a secret.
func (v RegistryValue) canonical() (string, error) {
	switch v.Type {
	case "dword":
		n, err := strconv.ParseUint(v.Data, 10, 32)
		if err != nil {
			return "", errors.New("data for a dword must be a decimal number up to 4294967295")
		}
		return strconv.FormatUint(n, 10), nil
	case "qword":
		n, err := strconv.ParseUint(v.Data, 10, 64)
		if err != nil {
			return "", errors.New("data for a qword must be a decimal number")
		}
		return strconv.FormatUint(n, 10), nil
	case "binary":
		b, err := hex.DecodeString(v.Data)
		if err != nil {
			return "", errors.New("data for binary must be hex, such as 0aff")
		}
		return hex.EncodeToString(b), nil
	case "multi_string":
		if strings.ContainsRune(v.Data, 0) || strings.Contains(v.Data, "\r") {
			return "", errors.New("data for a multi_string holds one value per line, with no NUL or carriage return")
		}
		return strings.TrimSuffix(v.Data, "\n"), nil
	}
	if strings.ContainsRune(v.Data, 0) {
		return "", errors.New("data must not contain NUL")
	}
	return v.Data, nil
}

// CheckData reports whether data can be stored as the value's type.
func (v RegistryValue) CheckData() error {
	_, err := v.canonical()
	return err
}

// Canonical is the value's data in the form Actual reports it, for hashing.
func (v RegistryValue) Canonical() (string, error) { return v.canonical() }

// ActualRegistry is a value on the host, in canonical form. It's only ever
// compared, never stored, so a secret can't reach state from here.
type ActualRegistry struct {
	Exists bool
	Type   string
	Data   string // empty when only the hash was asked for
	SHA256 string // lower-case hex of the canonical data, when asked for
}

// ReadRegistry reads a value, without expanding environment names. With
// hashOnly, the data never leaves the host: use that for a secret.
func ReadRegistry(ctx context.Context, r ps.Runner, v RegistryValue, hashOnly bool) (ActualRegistry, error) {
	sub, err := v.subKey()
	if err != nil {
		return ActualRegistry{}, err
	}
	res, err := ps.Read(ctx, r, script("read_registry.ps1"), map[string]any{"key": sub, "name": v.Name, "hash_only": hashOnly})
	if err != nil {
		return ActualRegistry{}, err
	}
	var raw struct {
		Exists bool            `json:"exists"`
		Kind   string          `json:"kind"`
		Data   json.RawMessage `json:"data"`
		SHA256 string          `json:"sha256"`
	}
	if err := json.Unmarshal(res.Value, &raw); err != nil {
		return ActualRegistry{}, errors.New("reading a registry value: the host's answer wasn't valid")
	}
	if !raw.Exists {
		return ActualRegistry{}, nil
	}
	a := ActualRegistry{Exists: true, SHA256: raw.SHA256}
	for name, kind := range registryKinds {
		if kind == raw.Kind {
			a.Type = name
		}
	}
	if hashOnly {
		return a, nil
	}
	switch a.Type {
	case "multi_string":
		var list []string
		if err := json.Unmarshal(raw.Data, &list); err != nil {
			return ActualRegistry{}, errors.New("reading a registry value: the host's answer wasn't valid")
		}
		a.Data = strings.Join(list, "\n")
	case "":
		// A type this module doesn't write, such as REG_NONE, can't match.
	default:
		var s string
		if err := json.Unmarshal(raw.Data, &s); err != nil {
			return ActualRegistry{}, errors.New("reading a registry value: the host's answer wasn't valid")
		}
		a.Data = s
	}
	switch a.Type {
	case "dword":
		// .NET reports stored bits as a signed number.
		n, err := strconv.ParseInt(a.Data, 10, 32)
		if err != nil {
			return ActualRegistry{}, errors.New("reading a registry value: the host's answer wasn't valid")
		}
		a.Data = strconv.FormatUint(uint64(uint32(n)), 10)
	case "qword":
		n, err := strconv.ParseInt(a.Data, 10, 64)
		if err != nil {
			return ActualRegistry{}, errors.New("reading a registry value: the host's answer wasn't valid")
		}
		a.Data = strconv.FormatUint(uint64(n), 10)
	case "binary":
		b, err := base64.StdEncoding.DecodeString(a.Data)
		if err != nil {
			return ActualRegistry{}, errors.New("reading a registry value: the host's answer wasn't valid")
		}
		a.Data = hex.EncodeToString(b)
	}
	return a, nil
}

// Matches reports whether the host holds the value as configured.
func (v RegistryValue) Matches(a ActualRegistry) (bool, error) {
	want, err := v.canonical()
	if err != nil {
		return false, err
	}
	return a.Exists && a.Type == v.Type && a.Data == want, nil
}

// ApplyRegistry writes a value, creating the key if needed. Errors have the
// data blanked.
func ApplyRegistry(ctx context.Context, r ps.Runner, v RegistryValue) error {
	sub, err := v.subKey()
	if err != nil {
		return err
	}
	data, err := v.canonical()
	if err != nil {
		return err
	}
	var wire any = data
	switch v.Type {
	case "binary":
		b, _ := hex.DecodeString(data)
		wire = base64.StdEncoding.EncodeToString(b)
	case "multi_string":
		wire = strings.Split(data, "\n")
	}
	_, err = ps.Apply(ctx, r, script("apply_registry.ps1"), map[string]any{"key": sub, "name": v.Name, "kind": registryKinds[v.Type], "data": wire}, time.Minute)
	if err != nil {
		return errors.New(Scrub(err.Error(), []string{v.Data, data}))
	}
	return nil
}

// ApplyRegistryRemove deletes a value and leaves the key.
func ApplyRegistryRemove(ctx context.Context, r ps.Runner, v RegistryValue) error {
	sub, err := v.subKey()
	if err != nil {
		return err
	}
	_, err = ps.Apply(ctx, r, script("apply_registry_remove.ps1"), map[string]any{"key": sub, "name": v.Name}, time.Minute)
	return err
}

// Service is the wanted state of a service. An empty field is left alone.
type Service struct {
	Name, StartMode, State string
}

// Validate checks a service before anything reaches a host. The name is also
// what keeps it out of wildcards and sc.exe's arguments.
func (s Service) Validate() error {
	if !serviceName.MatchString(s.Name) {
		return fmt.Errorf("service %q is not a service name", s.Name)
	}
	switch s.StartMode {
	case "", "auto", "delayed", "manual", "disabled":
	default:
		return fmt.Errorf(`start_mode %q must be "auto", "delayed", "manual" or "disabled"`, s.StartMode)
	}
	switch s.State {
	case "", "running", "stopped":
	default:
		return fmt.Errorf(`state %q must be "running" or "stopped"`, s.State)
	}
	if s.StartMode == "" && s.State == "" {
		return errors.New("set start_mode, state or both")
	}
	if s.StartMode == "disabled" && s.State == "running" {
		return errors.New("a disabled service can't be running")
	}
	return nil
}

// ServiceInSync reads a service. A service that doesn't exist is not in sync;
// apply reports it.
func ServiceInSync(ctx context.Context, r ps.Runner, s Service) (exists, inSync bool, err error) {
	res, err := ps.Read(ctx, r, script("read_service.ps1"), map[string]any{"name": s.Name})
	if err != nil {
		return false, false, err
	}
	var a struct {
		Exists  bool   `json:"exists"`
		Start   string `json:"start"`
		Delayed bool   `json:"delayed"`
		Status  string `json:"status"`
	}
	if err := json.Unmarshal(res.Value, &a); err != nil {
		return false, false, fmt.Errorf("reading service %s: %w", s.Name, err)
	}
	if !a.Exists {
		return false, false, nil
	}
	mode := map[string]string{"Automatic": "auto", "Manual": "manual", "Disabled": "disabled"}[a.Start]
	if mode == "auto" && a.Delayed {
		mode = "delayed"
	}
	inSync = (s.StartMode == "" || s.StartMode == mode) && (s.State == "" || strings.EqualFold(s.State, a.Status))
	return true, inSync, nil
}

// ApplyService sets a service's start mode and state.
func ApplyService(ctx context.Context, r ps.Runner, s Service) error {
	_, err := ps.Apply(ctx, r, script("apply_service.ps1"), map[string]any{"name": s.Name, "start_mode": s.StartMode, "state": s.State}, 5*time.Minute)
	return err
}

var featureName = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9-]{0,127}$`)

// Feature is a Windows Server role or feature.
type Feature struct {
	Name            string
	Absent          bool
	SubFeatures     bool
	ManagementTools bool
}

// Validate checks a feature before anything reaches a host. The name's
// characters also keep it out of wildcards.
func (f Feature) Validate() error {
	if !featureName.MatchString(f.Name) {
		return fmt.Errorf("feature %q is not a feature name, such as Web-Server", f.Name)
	}
	return nil
}

// FeatureInSync reads a feature. pending means it's waiting for a reboot.
func FeatureInSync(ctx context.Context, r ps.Runner, f Feature) (inSync, pending bool, err error) {
	res, err := ps.Read(ctx, r, script("read_feature.ps1"), map[string]any{
		"name": f.Name, "sub_features": f.SubFeatures && !f.Absent, "management_tools": f.ManagementTools && !f.Absent,
	})
	if err != nil {
		return false, false, err
	}
	var a struct {
		Exists    bool   `json:"exists"`
		State     string `json:"state"`
		Installed bool   `json:"installed"`
		// Missing lists the sub-features and tools asked for that aren't installed.
		Missing []string `json:"missing"`
	}
	if err := json.Unmarshal(res.Value, &a); err != nil {
		return false, false, fmt.Errorf("reading feature %s: %w", f.Name, err)
	}
	if !a.Exists {
		return false, false, fmt.Errorf("Windows has no feature named %s here", f.Name)
	}
	pending = strings.HasSuffix(a.State, "Pending")
	if f.Absent {
		return a.State == "Available" || a.State == "Removed" || a.State == "UninstallPending", pending, nil
	}
	return (a.Installed || a.State == "InstallPending") && len(a.Missing) == 0, pending, nil
}

// ApplyFeature installs or removes a feature and reports whether Windows wants
// a reboot for it. It never reboots.
func ApplyFeature(ctx context.Context, r ps.Runner, f Feature, timeout time.Duration) (restart bool, err error) {
	res, err := ps.Apply(ctx, r, script("apply_feature.ps1"), map[string]any{
		"name": f.Name, "present": !f.Absent, "sub_features": f.SubFeatures, "management_tools": f.ManagementTools,
	}, timeout)
	if err != nil {
		return false, err
	}
	var a struct {
		Restart bool `json:"restart"`
	}
	if err := json.Unmarshal(res.Value, &a); err != nil {
		return false, fmt.Errorf("reading the result for feature %s: %w", f.Name, err)
	}
	return a.Restart, nil
}
