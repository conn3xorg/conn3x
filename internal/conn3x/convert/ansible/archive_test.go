// Copyright (c) The Conn3x Authors
// SPDX-License-Identifier: MPL-2.0

package ansible

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// community.general.archive becomes a pack step. What the step would do
// differently, or more of, stays for review.
func TestConvertArchive(t *testing.T) {
	play := filepath.Join(t.TempDir(), "play.yml")
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
		"community.general.archive: {path: /var/log/app, dest: /backup/app.tgz, format: gz, force_archive: true}":            {"pack {", `paths  = ["/var/log/app"]`, `dest   = "/backup/app.tgz"`, `format = "gz"`, "0600"},
		"archive: {path: /var/log/app, dest: /backup/app.tar.gz, force_archive: yes, mode: '0640', owner: root, group: adm}": {`paths = ["/var/log/app"]`, `mode  = "0640"`, `owner = "root"`, `group = "adm"`},
		"archive: {path: [/etc/nginx, /etc/ssl/*.pem], dest: /backup/etc.zip, format: zip}":                                  {`paths  = ["/etc/nginx", "/etc/ssl/*.pem"]`, `format = "zip"`},
		"archive: {path: /etc/app, dest: /backup/app.xz, format: xz, force_archive: true}":                                   {`format = "xz"`},
		"archive: {path: /var/log/app, dest: /backup/app.tgz, force_archive: true, exclude_path: [/var/log/app/old], exclusion_patterns: ['*.gz', 'app/cache', /tmp/x]}": {
			`exclude = ["/var/log/app/old", "/var/log/*.gz", "/var/log/app/cache", "/tmp/x"]`,
		},
		"archive: {path: /srv/data, dest: /backup/d.tar, format: tar, remove: false, unsafe_writes: true}": {`format = "tar"`},
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
	if res := convert("archive: {path: /a/b, dest: /c.tgz, force_archive: true, mode: '0644'}"); strings.Contains(string(res.HCL), "Set mode") {
		t.Errorf("mode set, still a TODO:\n%s", res.HCL)
	}

	for task, reason := range map[string]string{
		"archive: {path: /var/log/app, dest: /backup/app.tgz, remove: true}":                        "remove: true",
		"archive: {path: /var/log/app.log, dest: /backup/app.log.gz}":                               "only force_archive says which",
		"archive: {path: /var/log/app, dest: /backup/app.tgz, format: gz}":                          "a dest named like a tar archive doesn't",
		"archive: {path: /var/log/app, dest: /backup/app.tar.xz, format: xz, force_archive: false}": "set force_archive: true",
		"archive: {path: /var/log/app.log}":                                                         "has no dest",
		"archive: {dest: /backup/a.tgz}":                                                            "has no path",
		"archive: {path: /var/log/app/, dest: /backup/app.tgz}":                                     "trailing slash",
		"archive: {path: /var/*/app, dest: /backup/app.tgz}":                                        "only the last part",
		"archive: {path: 'var/log', dest: /backup/app.tgz}":                                         "absolute path",
		"archive: {path: '/var/log/[ab]*', dest: /backup/app.tgz}":                                  "has a [",
		"archive: {path: /var/log, dest: /backup/a.rar, format: rar}":                               `format "rar"`,
		"archive: {path: /var/log, dest: /backup/a.tgz, mode: 'u+rw'}":                              "not an octal mode",
		"archive: {path: /var/log, dest: '{{ backup_dir }}/a.tgz'}":                                 "variable",
		"archive: {path: /var/log, dest: /backup/a.tgz, force_archive: true, attributes: +i}":       "attributes",
	} {
		res := convert(task)
		if res.Converted != 0 || !strings.Contains(reasons(res), reason) {
			t.Errorf("%s: converted %d, review %q, want %q\n%s", task, res.Converted, reasons(res), reason, res.HCL)
		}
	}
}
