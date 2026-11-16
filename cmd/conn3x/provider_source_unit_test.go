// Copyright (c) The Conn3x Authors
// SPDX-License-Identifier: MPL-2.0

package main

import (
	"context"
	"strings"
	"testing"

	"github.com/opentofu/opentofu/internal/addrs"
	"github.com/opentofu/opentofu/internal/command/cliconfig"
	"github.com/opentofu/opentofu/internal/command/cliconfig/ociauthconfig"
	"github.com/opentofu/opentofu/internal/getproviders"
	"github.com/opentofu/svchost/disco"
)

// An explicit provider_installation block keeps every method it can use
// and reports each it can't, with why.
func TestExplicitProviderSource(t *testing.T) {
	method := func(loc cliconfig.ProviderInstallationLocation, include, exclude []string) *cliconfig.ProviderInstallationMethod {
		return &cliconfig.ProviderInstallationMethod{Location: loc, Include: include, Exclude: exclude,
			Retries: func() (int, bool) { return 0, false }, Trusted: func() bool { return false }}
	}
	oci := cliconfig.ProviderInstallationOCIMirror{RepositoryMapping: func(p addrs.Provider) (string, string, error) {
		return "ghcr.io", "conn3xorg/" + p.Type, nil
	}}
	config := &cliconfig.ProviderInstallation{
		Methods: []*cliconfig.ProviderInstallationMethod{
			method(cliconfig.ProviderInstallationFilesystemMirror(t.TempDir()), []string{"conn3xorg/*"}, nil),
			method(cliconfig.ProviderInstallationNetworkMirror("https://mirror.example.com/providers/"), nil, []string{"conn3xorg/*"}),
			method(oci, nil, nil),
			method(cliconfig.ProviderInstallationNetworkMirror("http://mirror.example.com/"), nil, nil),
			method(cliconfig.ProviderInstallationNetworkMirror("https://[::1"), nil, nil),
			method(cliconfig.ProviderInstallationDirect, []string{"a/b/c/d"}, nil),
			method(cliconfig.ProviderInstallationDirect, nil, []string{"a/b/c/d"}),
		},
	}
	creds := func(context.Context) (ociauthconfig.CredentialsConfigs, error) {
		return ociauthconfig.CredentialsConfigs{}, nil
	}
	src, diags := providerSource(context.Background(), []*cliconfig.ProviderInstallation{config}, &cliconfig.RegistryProtocolsConfig{}, disco.New(), creds, t.TempDir())
	if len(diags) != 4 {
		t.Fatalf("diagnostics: %v", diags.Err())
	}
	for _, want := range []string{"must be at an https: URL", "Cannot parse", "invalid provider inclusion patterns", "invalid provider exclusion patterns"} {
		if !strings.Contains(diags.Err().Error(), want) {
			t.Errorf("no %q in %v", want, diags.Err())
		}
	}
	if multi, ok := src.(getproviders.MultiSource); !ok || len(multi) != 3 {
		t.Errorf("source = %#v", src)
	}
	if got := providerDevOverrides([]*cliconfig.ProviderInstallation{config}); got != nil {
		t.Errorf("dev overrides = %v", got)
	}
}
