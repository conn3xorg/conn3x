// Copyright (c) The Conn3x Authors
// SPDX-License-Identifier: MPL-2.0

package fetch

import (
	"strings"
	"testing"
)

const sum = "9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08"

func TestDownloadValidate(t *testing.T) {
	if err := (Download{URL: "https://example.com/a.tgz", Dest: "/opt/a.tgz", SHA256: sum}).Validate(); err != nil {
		t.Fatal(err)
	}
	for _, bad := range []Download{
		{URL: "ftp://example.com/a", Dest: "/opt/a", SHA256: sum},
		{URL: "https://example.com/a b", Dest: "/opt/a", SHA256: sum},
		{URL: "https://example.com/a", Dest: "opt/a", SHA256: sum},
		{URL: "https://example.com/a", Dest: "/opt/a", SHA256: ""},
		{URL: "https://example.com/a", Dest: "/opt/a", SHA256: strings.ToUpper(sum)[:63]},
		{URL: "https://example.com/a", Dest: "/opt/a", SHA256: sum, Mode: "rwx"},
	} {
		if bad.Validate() == nil {
			t.Errorf("accepted %+v", bad)
		}
	}
}

func TestArchiveValidate(t *testing.T) {
	if err := (Archive{Src: "/tmp/a.tgz", Dest: "/opt/a", Creates: "/opt/a/bin/a"}).Validate(); err != nil {
		t.Fatal(err)
	}
	for _, bad := range []Archive{
		{Src: "a.tgz", Dest: "/opt/a", Creates: "/opt/a/x"},
		{Src: "/tmp/a.tgz", Dest: "/opt/a", Creates: ""},
		{Src: "/tmp/a.tgz", Dest: "relative", Creates: "/opt/a/x"},
	} {
		if bad.Validate() == nil {
			t.Errorf("accepted %+v", bad)
		}
	}
}

func TestGitValidate(t *testing.T) {
	for _, ok := range []Git{
		{Repo: "https://github.com/octocat/Hello-World.git", Dest: "/srv/app"},
		{Repo: "git@github.com:octocat/Hello-World.git", Dest: "/srv/app", Ref: "v1.2.3"},
		{Repo: "ssh://git@example.com/app.git", Dest: "/srv/app", Ref: "release/2026"},
	} {
		if err := ok.Validate(); err != nil {
			t.Errorf("rejected %+v: %v", ok, err)
		}
	}
	for _, bad := range []Git{
		{Repo: "", Dest: "/srv/app"},
		{Repo: "https://example.com/a b", Dest: "/srv/app"},
		{Repo: "--upload-pack=touch /tmp/x", Dest: "/srv/app"},
		{Repo: "https://example.com/a.git", Dest: "srv"},
		{Repo: "https://example.com/a.git", Dest: "/srv/app", Ref: "-x"},
		{Repo: "https://example.com/a.git", Dest: "/srv/app", Ref: "main;reboot"},
	} {
		if bad.Validate() == nil {
			t.Errorf("accepted %+v", bad)
		}
	}
}

func TestResolve(t *testing.T) {
	out := "aaaa000000000000000000000000000000000001\tHEAD\n" +
		"aaaa000000000000000000000000000000000002\trefs/heads/main\n" +
		"aaaa000000000000000000000000000000000003\trefs/tags/v1\n" +
		"aaaa000000000000000000000000000000000004\trefs/tags/v1^{}\n"
	for ref, want := range map[string]string{
		"HEAD": "aaaa000000000000000000000000000000000001",
		"main": "aaaa000000000000000000000000000000000002",
		"v1":   "aaaa000000000000000000000000000000000004",
	} {
		if got, err := resolve(out, ref); err != nil || got != want {
			t.Errorf("resolve(%q) = %q, %v; want %q", ref, got, err, want)
		}
	}
	if got, err := resolve("", "7fd1a60b01f91b314f59955a4e4d4e80d8edf11d"); err != nil || got != "7fd1a60b01f91b314f59955a4e4d4e80d8edf11d" {
		t.Errorf("a full commit resolves to itself: %q, %v", got, err)
	}
	if _, err := resolve(out, "nope"); err == nil {
		t.Error("resolved a ref the remote does not have")
	}
}
