// Copyright (c) The Conn3x Authors
// SPDX-License-Identifier: MPL-2.0

package windows

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/url"
	"regexp"
	"sort"
	"strings"
	"time"

	"github.com/opentofu/opentofu/internal/conn3x/modules/windows/ps"
)

var (
	productCode = regexp.MustCompile(`^\{[0-9A-F]{8}-[0-9A-F]{4}-[0-9A-F]{4}-[0-9A-F]{4}-[0-9A-F]{12}\}$`)
	sha256Hex   = regexp.MustCompile(`^[0-9a-f]{64}$`)
	// Public MSI properties are upper case; this also keeps = and spaces out.
	msiProperty = regexp.MustCompile(`^[A-Z_][A-Z0-9_.]{0,71}$`)
)

// Package is an MSI. Present needs SHA256 and one of Source, a file already on
// the host, or URL. Properties go on msiexec's command line, so no secrets.
type Package struct {
	ProductCode string
	Absent      bool
	Source      string
	URL         string
	SHA256      string
	Properties  map[string]string
}

// Validate checks a package before anything reaches a host.
func (p Package) Validate() error {
	if !productCode.MatchString(strings.ToUpper(p.ProductCode)) {
		return fmt.Errorf("product_code %q must be a GUID in braces, such as {23170F69-40C1-2702-2409-000001000000}", p.ProductCode)
	}
	if p.Absent {
		return nil
	}
	if (p.Source == "") == (p.URL == "") {
		return errors.New("set exactly one of source and url")
	}
	if p.Source != "" {
		if _, err := CleanLocalPath("source", p.Source); err != nil {
			return err
		}
	}
	if p.URL != "" {
		u, err := url.Parse(p.URL)
		if err != nil || (u.Scheme != "https" && u.Scheme != "http") || u.Host == "" || strings.ContainsFunc(p.URL, func(r rune) bool { return r < 0x21 || r == 0x7f }) {
			return fmt.Errorf("url %q must be an http or https address", p.URL)
		}
	}
	if !sha256Hex.MatchString(strings.ToLower(p.SHA256)) {
		return errors.New("sha256 must be the package's SHA-256, as 64 hex characters")
	}
	_, err := msiProperties(p.Properties)
	return err
}

// msiProperties renders properties the way msiexec reads them: NAME="value",
// with a quote in a value doubled. msiexec parses its own command line, so
// these are its rules, not the C runtime's.
func msiProperties(props map[string]string) (string, error) {
	names := make([]string, 0, len(props))
	for k := range props {
		names = append(names, k)
	}
	sort.Strings(names)
	var out []string
	for _, k := range names {
		v := props[k]
		if !msiProperty.MatchString(k) {
			return "", fmt.Errorf("property %q must be a public property name: upper-case letters, digits, _ and .", k)
		}
		if strings.ContainsFunc(v, func(r rune) bool { return r < 0x20 || r == 0x7f }) {
			return "", fmt.Errorf("property %s has a control character in its value", k)
		}
		out = append(out, k+`="`+strings.ReplaceAll(v, `"`, `""`)+`"`)
	}
	return strings.Join(out, " "), nil
}

// PackageInstalled reports whether Windows lists the product as installed,
// from the Uninstall keys in both registry views. It never asks Win32_Product,
// which can start a repair of every MSI on the host.
func PackageInstalled(ctx context.Context, r ps.Runner, code string) (bool, error) {
	res, err := ps.Read(ctx, r, script("read_package.ps1"), map[string]any{"code": strings.ToUpper(code)})
	if err != nil {
		return false, err
	}
	var a struct {
		Installed bool `json:"installed"`
	}
	if err := json.Unmarshal(res.Value, &a); err != nil {
		return false, fmt.Errorf("reading package %s: the host's answer wasn't valid", code)
	}
	return a.Installed, nil
}

// ApplyPackage installs or removes an MSI and reports whether Windows wants a
// reboot for it. It never reboots: a reboot it needs is recorded on the host,
// where windows_reboot finds it, even if this run stops before then.
func ApplyPackage(ctx context.Context, r ps.Runner, p Package, timeout time.Duration) (restart bool, err error) {
	if err := p.Validate(); err != nil {
		return false, err
	}
	props, _ := msiProperties(p.Properties)
	res, err := ps.Apply(ctx, r, script("apply_package.ps1"), map[string]any{
		"present": !p.Absent, "product_code": strings.ToUpper(p.ProductCode), "source": p.Source, "url": p.URL,
		"sha256": strings.ToLower(p.SHA256), "properties": props,
	}, timeout)
	if err != nil {
		return false, err
	}
	var a struct {
		Restart bool `json:"restart"`
	}
	if err := json.Unmarshal(res.Value, &a); err != nil {
		return false, fmt.Errorf("reading the result for package %s: %w", p.ProductCode, err)
	}
	return a.Restart, nil
}
