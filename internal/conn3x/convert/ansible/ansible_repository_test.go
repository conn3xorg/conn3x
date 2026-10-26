// Copyright (c) The Conn3x Authors
// SPDX-License-Identifier: MPL-2.0

package ansible

import (
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"

	"github.com/hashicorp/hcl/v2/hclparse"
)

const asciiArmoredKey = "-----BEGIN PGP PUBLIC KEY BLOCK-----\n\nmQINBF\n-----END PGP PUBLIC KEY BLOCK-----\n"

func repositoryPlaybook(t *testing.T, dir, task string) Result {
	t.Helper()
	path := filepath.Join(dir, "play.yml")
	src := "- hosts: all\n  tasks:\n    - " + task + "\n"
	if err := os.WriteFile(path, []byte(src), 0o644); err != nil {
		t.Fatal(err)
	}
	res, err := Convert(path)
	if err != nil {
		t.Fatal(err)
	}
	if _, diags := hclparse.NewParser().ParseHCL(res.HCL, "play.tf"); diags.HasErrors() {
		t.Fatalf("output is not valid HCL: %s\n%s", diags, res.HCL)
	}
	return res
}

func TestConvertsRepositoryTasksWithALocalKey(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "key.asc"), []byte(asciiArmoredKey), 0o644); err != nil {
		t.Fatal(err)
	}
	for name, task := range map[string]string{
		"yum": "yum_repository: {name: nginx, baseurl: 'https://nginx.org/packages/centos/7/x86_64/', key_file: key.asc}",
		"apt": "apt_repository: {repo: 'deb https://nginx.org/packages/ubuntu noble main extra', key_file: key.asc}",
	} {
		t.Run(name, func(t *testing.T) {
			res := repositoryPlaybook(t, dir, task)
			if res.Converted != 1 || len(res.Review) != 0 {
				t.Fatalf("converted %d, review %+v\n%s", res.Converted, res.Review, res.HCL)
			}
			if !strings.Contains(string(res.HCL), `repository {`) ||
				!regexp.MustCompile(`key\s+= "-----BEGIN PGP PUBLIC KEY BLOCK-----`).Match(res.HCL) {
				t.Fatalf("repository step lacks the signing key:\n%s", res.HCL)
			}
		})
	}
}

func TestRepositoryRefusalsKeepTheTaskForReview(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "key.asc"), []byte(asciiArmoredKey), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "key.gpg"), []byte("binary"), 0o644); err != nil {
		t.Fatal(err)
	}
	cases := []struct{ reason, task string }{
		{"no signing key", "yum_repository: {name: nginx, baseurl: https://example.com/repo}"},
		{"binary key", "apt_repository: {repo: 'deb https://example.com/repo noble main extra', key_file: key.gpg}"},
		{"URL with a variable", "yum_repository: {name: nginx, baseurl: 'https://example.com/$releasever', key_file: key.asc}"},
		{"gpgcheck to false", "yum_repository: {name: nginx, baseurl: https://example.com/repo, gpgcheck: false, key_file: key.asc}"},
		{"mirrorlist", "yum_repository: {name: nginx, mirrorlist: https://example.com/mirror, key_file: key.asc}"},
		{"repo line with options", "apt_repository: {repo: 'deb [arch=amd64] https://example.com/repo noble main', key_file: key.asc}"},
		{"could not read", "apt_repository: {repo: 'deb https://example.com/repo noble main', key_file: missing.asc}"},
	}
	for _, c := range cases {
		t.Run(c.reason, func(t *testing.T) {
			res := repositoryPlaybook(t, dir, c.task)
			if res.Converted != 0 || len(res.Review) != 1 || !strings.Contains(res.Review[0].Reason, c.reason) {
				t.Fatalf("converted %d, review %+v\n%s", res.Converted, res.Review, res.HCL)
			}
			if !strings.Contains(string(res.HCL), "TODO(convert)") {
				t.Fatalf("refusal did not leave the task beside a TODO:\n%s", res.HCL)
			}
		})
	}
}
