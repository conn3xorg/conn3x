// Copyright (c) The Conn3x Authors
// SPDX-License-Identifier: MPL-2.0

package windows

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"regexp"
	"strings"
	"time"

	"github.com/opentofu/opentofu/internal/conn3x/modules/windows/ps"
)

// Certificate is a certificate file on the host, imported into a store.
type Certificate struct {
	Path     string // a .cer, .crt or .der, or a .pfx or .p12
	Location string // LocalMachine or CurrentUser
	Store    string // My, Root, CA, TrustedPeople, WebHosting, ...
	Password string // a PFX's, at apply only
	Absent   bool
}

var (
	certPath  = regexp.MustCompile(`(?i)^[a-z]:\\[^\x00-\x1f*?"<>|]+\.(cer|crt|der|pfx|p12)$`)
	storeName = regexp.MustCompile(`^[A-Za-z][A-Za-z0-9]{0,63}$`)
)

// PFX reports whether the file holds a private key, by its extension.
func (c Certificate) PFX() bool {
	l := strings.ToLower(c.Path)
	return strings.HasSuffix(l, ".pfx") || strings.HasSuffix(l, ".p12")
}

// Validate checks a certificate's settings before anything reaches the host.
func (c Certificate) Validate() error {
	if !certPath.MatchString(c.Path) {
		return fmt.Errorf("path %q must be a certificate file on the host, ending in .cer, .crt, .der, .pfx or .p12, such as C:\\certs\\web.pfx", c.Path)
	}
	if c.Location != "LocalMachine" && c.Location != "CurrentUser" {
		return fmt.Errorf(`store_location must be "LocalMachine" or "CurrentUser", not %q`, c.Location)
	}
	if !storeName.MatchString(c.Store) {
		return fmt.Errorf("store_name %q must be a store's name, such as My, Root, CA or TrustedPeople", c.Store)
	}
	return nil
}

// ActualCertificate is what a read finds: the certificate in the store, by
// the thumbprint the last apply recorded, and the file as it is now.
type ActualCertificate struct {
	InStore    bool
	HasKey     bool
	FileExists bool
	FileSHA256 string
}

// ReadCertificate looks for thumbprint in the store and hashes the file.
func ReadCertificate(ctx context.Context, r ps.Runner, c Certificate, thumbprint string) (ActualCertificate, error) {
	res, err := ps.Read(ctx, r, script("read_certificate.ps1"), map[string]any{"path": c.Path, "location": c.Location, "store": c.Store, "thumbprint": thumbprint})
	if err != nil {
		return ActualCertificate{}, err
	}
	var raw struct {
		InStore    bool   `json:"in_store"`
		HasKey     bool   `json:"has_key"`
		FileExists bool   `json:"file_exists"`
		FileSHA256 string `json:"file_sha256"`
	}
	if err := json.Unmarshal(res.Value, &raw); err != nil {
		return ActualCertificate{}, errors.New("reading a certificate: the host's answer wasn't valid")
	}
	return ActualCertificate(raw), nil
}

// Matches reports whether the store has the certificate the last apply put
// there and, while the file is still on the host, that the file is the one
// it came from: a renewed file is drift. A file removed after the import,
// as is common for a PFX, doesn't count.
func (c Certificate) Matches(a ActualCertificate, sha256 string) bool {
	if c.Absent {
		return !a.InStore
	}
	if !a.InStore || (c.PFX() && !a.HasKey) {
		return false
	}
	return !a.FileExists || sha256 == "" || a.FileSHA256 == sha256
}

// ApplyCertificate imports the file, or with Absent removes the certificate
// by thumbprint, and returns the thumbprint and the file's SHA-256.
func ApplyCertificate(ctx context.Context, r ps.Runner, c Certificate, thumbprint string) (string, string, error) {
	if err := c.Validate(); err != nil {
		return "", "", err
	}
	args := map[string]any{"path": c.Path, "location": c.Location, "store": c.Store, "thumbprint": thumbprint, "pfx": c.PFX(), "password": c.Password, "drop": c.Absent}
	res, err := ps.Apply(ctx, r, script("apply_certificate.ps1"), args, 2*time.Minute)
	if err != nil {
		return "", "", errors.New(Scrub(err.Error(), []string{c.Password}))
	}
	var out struct {
		Thumbprint string `json:"thumbprint"`
		SHA256     string `json:"sha256"`
	}
	if err := json.Unmarshal(res.Value, &out); err != nil {
		return "", "", errors.New("importing a certificate: the host's answer wasn't valid")
	}
	return out.Thumbprint, out.SHA256, nil
}
