// Copyright (c) The Conn3x Authors
// SPDX-License-Identifier: MPL-2.0

// Package windows holds the host modules for Windows.
//
// Scripts live in embedded files and take values only through the $A hashtable
// the stub hands them, so a value can never become code. Rules enforced by
// rules_test.go and scripts/ps-rules.ps1, not by convention:
//
//   - read_*.ps1 scripts change nothing, and only ps.Read runs them.
//   - apply_*.ps1 scripts run through ps.Apply, from Apply* functions only.
//   - A script reaches ps.Read or ps.Apply only as script("literal.ps1").
package windows

import (
	"bytes"
	"context"
	"embed"
	"encoding/json"
	"errors"
	"fmt"
	"regexp"
	"strings"
	"time"

	"github.com/opentofu/opentofu/internal/conn3x/modules/windows/ps"
)

//go:embed *.ps1 lib/*.ps1
var scripts embed.FS

var includeLine = regexp.MustCompile(`(?m)^#include ([a-z]+)\r?$`)

// script returns an embedded script, with lib/NAME.ps1 in place of each
// #include NAME line. A missing one is a bug in this package, and a test reads
// every name passed here.
func script(name string) ps.Script {
	b, err := scripts.ReadFile(name)
	if err != nil {
		panic(err)
	}
	body := includeLine.ReplaceAllStringFunc(string(b), func(line string) string {
		lib, err := scripts.ReadFile("lib/" + includeLine.FindStringSubmatch(line)[1] + ".ps1")
		if err != nil {
			panic(err)
		}
		return string(lib)
	})
	return ps.Script{Name: name, Body: body}
}

// readBool runs a read script whose output is a single boolean.
func readBool(ctx context.Context, r ps.Runner, s ps.Script, args map[string]any) (bool, error) {
	res, err := ps.Read(ctx, r, s, args)
	if err != nil {
		return false, err
	}
	var ok bool
	if err := json.Unmarshal(res.Value, &ok); err != nil {
		return false, fmt.Errorf("%s returned %q, not a boolean", s.Name, res.Value)
	}
	return ok, nil
}

// Facts describe a Windows host.
type Facts struct {
	Version          string
	Build            string
	UBR              int // update build revision: the patch level within Build
	Arch             string
	CPUs             int
	MemoryMB         int
	IPv4             string
	Release          string // "2025", "2022", or "" for a build not listed here
	Edition          string
	InstallationType string
	Hostname         string
	Domain           string
	DomainRole       int
	PowerShell       string
	Elevated         bool
}

// serverReleases names Windows Server releases by build number. Names come
// from here because display text is localised.
var serverReleases = map[string]string{"26100": "2025", "20348": "2022", "17763": "2019"}

var archNames = map[string]string{"AMD64": "x86_64", "ARM64": "aarch64"}

// What a fact may hold. A hostname or domain may have letters of any
// script, a workgroup's name may have spaces, and the installation type
// is "Server Core" on Core.
var (
	factWord  = regexp.MustCompile(`^[A-Za-z0-9._-]*$`)
	factName  = regexp.MustCompile(`^[\p{L}\p{N}._-]*$`)
	factWords = regexp.MustCompile(`^[\p{L}\p{N} ._-]*$`)
)

// Gather reads the facts from a host, failing on anything but Windows Server.
func Gather(ctx context.Context, r ps.Runner) (Facts, error) {
	res, err := ps.Read(ctx, r, script("read_facts.ps1"), nil)
	if err != nil {
		return Facts{}, err
	}
	var raw struct {
		Version          string `json:"version"`
		Build            string `json:"build"`
		UBR              int    `json:"ubr"`
		ProductType      int    `json:"product_type"`
		Arch             string `json:"arch"`
		CPUs             int    `json:"cpus"`
		MemoryKB         int64  `json:"memory_kb"`
		IPv4             string `json:"ipv4"`
		Edition          string `json:"edition"`
		InstallationType string `json:"installation_type"`
		Hostname         string `json:"hostname"`
		Domain           string `json:"domain"`
		DomainRole       int    `json:"domain_role"`
		PowerShell       string `json:"powershell"`
		Elevated         bool   `json:"elevated"`
	}
	if err := json.Unmarshal(res.Value, &raw); err != nil {
		return Facts{}, fmt.Errorf("reading Windows facts: %w", err)
	}
	// The host reports its own facts, and a circuit may put one into a
	// command for another host: none carries shell syntax or control
	// characters. Version, arch and ipv4 are checked with the Linux facts.
	for _, f := range []struct {
		name, value string
		plain       *regexp.Regexp
	}{
		{"build", raw.Build, factWord}, {"edition", raw.Edition, factWord}, {"PowerShell version", raw.PowerShell, factWord},
		{"hostname", raw.Hostname, factName}, {"domain", raw.Domain, factWords},
		{"installation type", raw.InstallationType, factWords},
	} {
		if !f.plain.MatchString(f.value) {
			return Facts{}, fmt.Errorf("the host reported a %s that isn't a plain word: %q", f.name, f.value)
		}
	}
	if raw.ProductType == 1 {
		return Facts{}, fmt.Errorf("%s is Windows client %s; Conn3x manages Windows Server only", raw.Hostname, raw.Version)
	}
	arch := raw.Arch
	if n, ok := archNames[arch]; ok {
		arch = n
	}
	return Facts{
		Version: raw.Version, Build: raw.Build, UBR: raw.UBR, Arch: arch, CPUs: raw.CPUs, MemoryMB: int(raw.MemoryKB / 1024), IPv4: raw.IPv4,
		Release: serverReleases[raw.Build], Edition: raw.Edition, InstallationType: raw.InstallationType, Hostname: raw.Hostname,
		Domain: raw.Domain, DomainRole: raw.DomainRole, PowerShell: raw.PowerShell, Elevated: raw.Elevated,
	}, nil
}

// Elevated reports whether the login holds an elevated token.
func Elevated(ctx context.Context, r ps.Runner) (bool, error) {
	return readBool(ctx, r, script("read_elevated.ps1"), nil)
}

// BootID identifies the host's current boot; it changes on every reboot.
func BootID(ctx context.Context, r ps.Runner) (string, error) {
	res, err := ps.Read(ctx, r, script("read_boot_id.ps1"), nil)
	if err != nil {
		return "", err
	}
	var id string
	if err := json.Unmarshal(res.Value, &id); err != nil || id == "" {
		return "", fmt.Errorf("reading the boot id: got %q", res.Value)
	}
	return id, nil
}

// PendingReboot reports whether Windows is waiting for a reboot.
func PendingReboot(ctx context.Context, r ps.Runner) (bool, error) {
	return readBool(ctx, r, script("read_pending_reboot.ps1"), nil)
}

// ApplyReboot starts a reboot five seconds from now and returns before the
// connection drops.
func ApplyReboot(ctx context.Context, r ps.Runner) error {
	_, err := ps.Apply(ctx, r, script("apply_reboot.ps1"), nil, time.Minute)
	if err != nil {
		return fmt.Errorf("scheduling a reboot: %w", err)
	}
	return nil
}

var (
	windowsPath = regexp.MustCompile(`^[A-Za-z]:[\\/]`)
	serviceName = regexp.MustCompile(`^[A-Za-z0-9_.$@ -]{1,256}$`)
)

// ValidatePath checks a path before anything reaches a host: an absolute path
// on a local drive, with no control characters. A share or a device path would
// have the host contact another machine, or a driver, just to read it.
func ValidatePath(attr, p string) error {
	if !windowsPath.MatchString(p) {
		return fmt.Errorf(`%s %q must be an absolute path on a local drive, such as C:\app\ready`, attr, p)
	}
	if strings.ContainsFunc(p, func(r rune) bool { return r < 0x20 || r == 0x7f }) {
		return fmt.Errorf("%s %q must not contain control characters", attr, p)
	}
	if strings.ContainsAny(p[2:], `<>"|?*`) {
		return fmt.Errorf(`%s %q has a character Windows doesn't allow in a path: < > " | ? *`, attr, p)
	}
	return nil
}

// DefaultWait is how long WaitFor waits when no timeout is given.
const DefaultWait = 5 * time.Minute

// WaitFor waits until a path exists, a service runs or a TCP port is listening.
type WaitFor struct {
	Path    string
	Service string
	Port    int
	Timeout time.Duration
}

// Validate checks a WaitFor before anything reaches the host.
func (w WaitFor) Validate() error {
	set := 0
	for _, b := range []bool{w.Path != "", w.Service != "", w.Port != 0} {
		if b {
			set++
		}
	}
	switch {
	case set != 1:
		return errors.New("set exactly one of path, service or port")
	case w.Path != "":
		_, err := CleanLocalPath("path", w.Path)
		return err
	case w.Service != "" && !serviceName.MatchString(w.Service):
		return fmt.Errorf("service %q is not a service name", w.Service)
	case w.Service == "" && (w.Port < 1 || w.Port > 65535):
		return fmt.Errorf("port %d is out of range 1 to 65535", w.Port)
	}
	return nil
}

func (w WaitFor) String() string {
	switch {
	case w.Path != "":
		return w.Path
	case w.Service != "":
		return "service " + w.Service
	}
	return fmt.Sprintf("port %d", w.Port)
}

// Ready reports whether the wait is already over.
func (w WaitFor) Ready(ctx context.Context, r ps.Runner) (bool, error) {
	return readBool(ctx, r, script("read_wait.ps1"), map[string]any{"path": w.Path, "service": w.Service, "port": w.Port})
}

// Guards decide whether a script still needs to run. Any guard that is set
// must hold for the script to count as done.
type Guards struct {
	Creates string // done once this path exists
	Removes string // done once this path is gone
	Unless  string // done while this PowerShell check holds
}

// Any reports whether at least one guard is set.
func (g Guards) Any() bool { return g.Creates != "" || g.Removes != "" || g.Unless != "" }

// Validate checks the guards before anything runs on a host.
func (g Guards) Validate() error {
	if g.Creates != "" {
		if _, err := CleanLocalPath("creates", g.Creates); err != nil {
			return err
		}
	}
	if g.Removes != "" {
		if _, err := CleanLocalPath("removes", g.Removes); err != nil {
			return err
		}
	}
	return nil
}

// Satisfied reports whether every guard holds. With no guards there is nothing
// to check, so it reports false. The check in Unless holds unless it throws,
// a native program it ran exits non-zero, or its last output is $false, as
// from Test-Path.
func Satisfied(ctx context.Context, r ps.Runner, g Guards, args map[string]any) (bool, error) {
	if !g.Any() {
		return false, nil
	}
	if g.Creates != "" || g.Removes != "" {
		ok, err := readBool(ctx, r, script("read_guards.ps1"), map[string]any{"creates": g.Creates, "removes": g.Removes})
		if err != nil || !ok {
			return false, err
		}
	}
	if g.Unless == "" {
		return true, nil
	}
	res, err := ps.User(ctx, r, g.Unless, args, ps.ReadTimeout)
	if err != nil {
		var noResult *ps.NoResultError
		if errors.As(err, &noResult) || ctx.Err() != nil {
			return false, err
		}
		return false, nil // the check threw: it doesn't hold
	}
	return res.ExitCode == 0 && string(res.Value) != "false", nil
}

// MaxOutput is how much of a script's output is kept.
const MaxOutput = 4096

// Output is what a script printed.
type Output struct {
	Stdout, Stderr string
}

// RunScript runs a user's script. Secrets are the values to blank from what it
// printed and from its errors, which end up in state and logs. A script fails
// by throwing, or when the last native program it ran exits non-zero.
func RunScript(ctx context.Context, r ps.Runner, code string, args map[string]any, secrets []string, timeout time.Duration) (Output, error) {
	res, err := ps.User(ctx, r, code, args, timeout)
	out := Output{Stdout: clip(Scrub(res.Stdout+res.Text, secrets)), Stderr: clip(Scrub(res.Stderr, secrets))}
	if err != nil {
		return out, errors.New(Scrub(err.Error(), secrets))
	}
	if res.ExitCode != 0 {
		msg := strings.TrimSpace(out.Stderr)
		if msg == "" {
			msg = strings.TrimSpace(out.Stdout)
		}
		return out, fmt.Errorf("the script's last native program exited with %d: %s", res.ExitCode, msg)
	}
	return out, nil
}

const blanked = "(sensitive value)"

// Scrub blanks secrets from text bound for state or logs. PowerShell may wrap a
// long value, indent what follows or change its line endings, so line breaks
// and spaces don't count when matching, in the text or in the secret. Blanking
// a little too much is fine; missing the middle of a key isn't.
func Scrub(s string, secrets []string) string {
	for _, v := range secrets {
		if v != "" {
			s = scrubSpaced(strings.ReplaceAll(s, v, blanked), v)
		}
	}
	return s
}

func isSpacing(c byte) bool { return c == '\r' || c == '\n' || c == ' ' || c == '\t' }

func scrubSpaced(s, secret string) string {
	want := make([]byte, 0, len(secret))
	for i := 0; i < len(secret); i++ {
		if !isSpacing(secret[i]) {
			want = append(want, secret[i])
		}
	}
	if len(want) == 0 {
		return s
	}
	// flat is s without spacing; at says where each of its bytes came from.
	flat, at := make([]byte, 0, len(s)), make([]int, 0, len(s))
	for i := 0; i < len(s); i++ {
		if !isSpacing(s[i]) {
			flat, at = append(flat, s[i]), append(at, i)
		}
	}
	var out strings.Builder
	last, pos := 0, 0
	for {
		i := bytes.Index(flat[pos:], want)
		if i < 0 {
			break
		}
		start, end := pos+i, pos+i+len(want)
		out.WriteString(s[last:at[start]])
		out.WriteString(blanked)
		last, pos = at[end-1]+1, end
	}
	out.WriteString(s[last:])
	return out.String()
}

func clip(s string) string {
	if len(s) <= MaxOutput {
		return s
	}
	return s[:MaxOutput] + "\n[output truncated]"
}
