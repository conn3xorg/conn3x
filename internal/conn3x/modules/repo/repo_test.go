// Copyright (c) The Conn3x Authors
// SPDX-License-Identifier: MPL-2.0

package repo

import (
	"strings"
	"testing"

	"github.com/opentofu/opentofu/internal/conn3x/modules/pkg"
)

const key = "-----BEGIN PGP PUBLIC KEY BLOCK-----\n\nmQINBF\n-----END PGP PUBLIC KEY BLOCK-----\n"

func TestRPMFiles(t *testing.T) {
	r := Repo{Name: "nginx-stable", URL: "https://nginx.org/packages/centos/$releasever/$basearch/", Key: key}
	if err := r.Validate(pkg.RPM); err != nil {
		t.Fatal(err)
	}
	files := r.Files(pkg.RPM)
	if got := files["/etc/pki/rpm-gpg/RPM-GPG-KEY-conn3x-nginx-stable"]; got != key {
		t.Fatalf("key file = %q", got)
	}
	want := "# Managed by Conn3x.\n[nginx-stable]\nname=nginx-stable\nbaseurl=https://nginx.org/packages/centos/$releasever/$basearch/\nenabled=1\ngpgcheck=1\ngpgkey=file:///etc/pki/rpm-gpg/RPM-GPG-KEY-conn3x-nginx-stable\n"
	if got := files["/etc/yum.repos.d/nginx-stable.repo"]; got != want {
		t.Fatalf("repo file = %q", got)
	}
	if len(files) != 2 {
		t.Fatalf("files = %v", files)
	}
}

func TestDebFiles(t *testing.T) {
	r := Repo{Name: "nginx", URL: "https://nginx.org/packages/ubuntu", Key: key, Suites: []string{"noble"}}
	if err := r.Validate(pkg.Deb); err != nil {
		t.Fatal(err)
	}
	files := r.Files(pkg.Deb)
	if got := files["/etc/apt/keyrings/conn3x-nginx.asc"]; got != key {
		t.Fatalf("key file = %q", got)
	}
	want := "# Managed by Conn3x.\nTypes: deb\nURIs: https://nginx.org/packages/ubuntu\nSuites: noble\nComponents: main\nSigned-By: /etc/apt/keyrings/conn3x-nginx.asc\n"
	if got := files["/etc/apt/sources.list.d/nginx.sources"]; got != want {
		t.Fatalf("sources file = %q", got)
	}
	flat := Repo{Name: "flat", URL: "https://example.com/repo", Key: key, Suites: []string{"./"}}
	if got := flat.Files(pkg.Deb)["/etc/apt/sources.list.d/flat.sources"]; strings.Contains(got, "Components") {
		t.Fatalf("a flat repository has no components: %q", got)
	}
}

func TestValidate(t *testing.T) {
	good := Repo{Name: "x", URL: "https://example.com/r", Key: key, Suites: []string{"noble"}}
	for _, bad := range []struct {
		r Repo
		f pkg.Family
	}{
		{Repo{Name: "bad name", URL: good.URL, Key: key}, pkg.RPM},
		{Repo{Name: "x", URL: "ftp://example.com", Key: key}, pkg.RPM},
		{Repo{Name: "x", URL: "https://example.com/a b", Key: key}, pkg.RPM},
		{Repo{Name: "x", URL: good.URL, Key: "not a key"}, pkg.RPM},
		{Repo{Name: "x", URL: good.URL, Key: key}, pkg.Deb},
		{Repo{Name: "x", URL: good.URL, Key: key, Suites: []string{"noble\nTypes: deb-src"}}, pkg.Deb},
		{Repo{Name: "x", URL: good.URL, Key: key, Suites: []string{"noble"}, Components: []string{"main universe"}}, pkg.Deb},
	} {
		if bad.r.Validate(bad.f) == nil {
			t.Errorf("accepted %+v for %s", bad.r, bad.f)
		}
	}
	if err := good.Validate(pkg.Deb); err != nil {
		t.Fatal(err)
	}
}
