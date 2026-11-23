// Copyright (c) The Conn3x Authors
// SPDX-License-Identifier: MPL-2.0

package ansible

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// ansible.posix.patch becomes a patch step: a src on the controller is
// read from files/ into content, one on the host stays src. What the step
// can't do the same way stays for review.
func TestConvertPatch(t *testing.T) {
	dir := t.TempDir()
	if err := os.MkdirAll(filepath.Join(dir, "files"), 0o755); err != nil {
		t.Fatal(err)
	}
	for _, f := range []string{"fix.patch", "tree.patch"} {
		if err := os.WriteFile(filepath.Join(dir, "files", f), []byte("--- a\n+++ b\n"), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	play := filepath.Join(dir, "play.yml")
	convert := func(task string) Result {
		t.Helper()
		if err := os.WriteFile(play, []byte("- hosts: all\n  tasks:\n    - "+task+"\n"), 0o644); err != nil {
			t.Fatal(err)
		}
		res, err := Convert(play)
		if err != nil {
			t.Fatal(err)
		}
		return res
	}

	for task, want := range map[string][]string{
		"ansible.posix.patch: {src: fix.patch, dest: /etc/app.conf}":                   {"patch {", `content = file("${path.module}/files/fix.patch")`, `dest    = "/etc/app.conf"`},
		"patch: {src: fix.patch, dest: /etc/app.conf, remote_src: false, backup: yes}": {`content = file(`, "backup dropped"},
		"patch: {src: /tmp/fix.patch, dest: /etc/app.conf, remote_src: true}":          {`src  = "/tmp/fix.patch"`, `dest = "/etc/app.conf"`},
		"patch: {src: tree.patch, basedir: /opt/app, strip: 1}":                        {`content = file("${path.module}/files/tree.patch")`, `basedir = "/opt/app"`, "strip   = 1"},
		"patch: {patchfile: fix.patch, originalfile: /etc/app.conf, state: absent, ignore_whitespace: true, binary: true}": {
			`state             = "absent"`, "ignore_whitespace = true", "binary            = true",
		},
	} {
		res := convert(task)
		if res.Converted != 1 || len(res.Review) != 0 {
			t.Errorf("%s: converted %d, review %+v\n%s", task, res.Converted, res.Review, res.HCL)
			continue
		}
		for _, w := range want {
			if !strings.Contains(string(res.HCL), w) {
				t.Errorf("%s: missing %q:\n%s", task, w, res.HCL)
			}
		}
	}

	for task, reason := range map[string]string{
		"patch: {src: fix.patch, dest: /etc/app.conf, basedir: /etc}":                 "sets both dest and basedir",
		"patch: {src: fix.patch}":                                                     "can't be a patch step",
		"patch: {dest: /etc/app.conf}":                                                "has no src",
		"patch: {src: missing.patch, dest: /etc/app.conf}":                            "missing.patch was not found",
		"patch: {src: fix.patch, dest: app.conf}":                                     "must be an absolute path",
		"patch: {src: tmp/fix.patch, dest: /etc/app.conf, remote_src: true}":          "must be an absolute path",
		"patch: {src: fix.patch, dest: /etc/app.conf, strip: one}":                    "strip that isn't a whole number",
		"patch: {src: fix.patch, dest: /etc/app.conf, strip: -1}":                     "strip must be 0 or more",
		"patch: {src: fix.patch, dest: '{{ conf_path }}'}":                            "variable",
		"patch: {src: /tmp/fix.patch, dest: /etc/app.conf, remote_src: true, foo: 1}": "foo",
	} {
		res := convert(task)
		if res.Converted != 0 || !strings.Contains(reasons(res), reason) {
			t.Errorf("%s: converted %d, review %q, want %q\n%s", task, res.Converted, reasons(res), reason, res.HCL)
		}
	}
}
