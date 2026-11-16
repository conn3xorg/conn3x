// Copyright (c) The Conn3x Authors
// SPDX-License-Identifier: MPL-2.0

package ansible

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestConvertSynchronize(t *testing.T) {
	dir := t.TempDir()
	if err := os.MkdirAll(filepath.Join(dir, "files", "site"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "files", "site", "index.html"), []byte("hi\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	play := filepath.Join(dir, "play.yml")
	convert := func(task string) Result {
		t.Helper()
		if err := os.WriteFile(play, []byte("- hosts: web\n  tasks:\n    - "+task+"\n"), 0o644); err != nil {
			t.Fatal(err)
		}
		res, err := Convert(play)
		if err != nil {
			t.Fatal(err)
		}
		return res
	}

	res := convert("ansible.posix.synchronize: { src: site/, dest: /var/www/site, delete: yes }")
	hcl := string(res.HCL)
	for _, want := range []string{"directory_copy {", `source      = "${path.module}/files/site"`, `destination = "/var/www/site"`, "delete      = true", "one mode"} {
		if !strings.Contains(hcl, want) {
			t.Errorf("missing %q:\n%s", want, hcl)
		}
	}
	if res.Converted != 1 {
		t.Errorf("converted %d, review %+v", res.Converted, res.Review)
	}
	// Without the slash, rsync puts the directory itself under dest.
	if hcl := string(convert("synchronize: { src: site, dest: /var/www }").HCL); !strings.Contains(hcl, `destination = "/var/www/site"`) {
		t.Errorf("src without a slash:\n%s", hcl)
	}

	for task, want := range map[string]string{
		"synchronize: { src: site/, dest: /srv, mode: pull }":              "mode: pull",
		"synchronize: { src: site/, dest: /srv, rsync_opts: [--exclude] }": "rsync options",
		"synchronize: { src: site/, dest: srv }":                           "relative dest",
		"synchronize: { src: nowhere/, dest: /srv }":                       "isn't in the playbook",
		"synchronize: { src: site/ }":                                      "needs src and dest",
		"synchronize: { src: site/, dest: /srv, copy_links: yes }":         "dirs or copy_links",
		"synchronize: { src: site/, dest: /srv, exclude: [a] }":            "filters what it copies",
	} {
		res := convert(task)
		if res.Converted != 0 || len(res.Review) != 1 || !strings.Contains(res.Review[0].Reason, want) {
			t.Errorf("%s: converted %d, review %+v, want %q", task, res.Converted, res.Review, want)
		}
	}
}

// In a role, the files synchronize copies go into the circuit, and a
// symlink among them is left for a person.
func TestConvertSynchronizeInARole(t *testing.T) {
	dir := t.TempDir()
	for p, body := range map[string]string{
		"tasks/main.yml":        "- ansible.posix.synchronize: { src: site/, dest: /var/www/site }\n",
		"files/site/index.html": "hi\n",
	} {
		if err := os.MkdirAll(filepath.Join(dir, filepath.Dir(p)), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(dir, p), []byte(body), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	res, err := ConvertRole(dir)
	if err != nil {
		t.Fatal(err)
	}
	if res.Converted != 1 || string(res.Files["files/site/index.html"]) != "hi\n" {
		t.Fatalf("converted %d, files %v, review %+v", res.Converted, res.Files, res.Review)
	}
	if err := os.Symlink("index.html", filepath.Join(dir, "files", "site", "home.html")); err != nil {
		t.Fatal(err)
	}
	if res, err = ConvertRole(dir); err != nil || res.Converted != 0 || len(res.Review) != 1 || !strings.Contains(res.Review[0].Reason, "is a link or a special file") {
		t.Errorf("with a symlink: %v, converted %d, review %+v", err, res.Converted, res.Review)
	}
}
