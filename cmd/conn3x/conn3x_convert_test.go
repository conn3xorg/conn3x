// Copyright (c) The Conn3x Authors
// SPDX-License-Identifier: MPL-2.0

package main

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestConvertRoleWritesANewDirectory(t *testing.T) {
	role := "../../internal/conn3x/convert/ansible/testdata/role/app"
	out := filepath.Join(t.TempDir(), "circuit-app")
	var errOut bytes.Buffer
	if code := runConvertRole(role, out, "", "", &errOut); code != 0 || !strings.Contains(errOut.String(), "Converted all 7 tasks.") {
		t.Fatalf("exited %d: %s", code, errOut.String())
	}
	for _, f := range []string{"main.circuit.hcl", "variables.tf", "outputs.tf", "README.md", "files/app.service", "templates/app.conf.tftpl"} {
		if _, err := os.Stat(filepath.Join(out, f)); err != nil {
			t.Error(err)
		}
	}
	// Converting again would replace what's there, so it refuses.
	errOut.Reset()
	if code := runConvertRole(role, out, "", "", &errOut); code != 1 || !strings.Contains(errOut.String(), "already has files") {
		t.Fatalf("second run exited %d: %s", code, errOut.String())
	}
	for args, want := range map[[3]string]string{
		{"", "", ""}:           "-role needs -out",
		{out, "site.yml", ""}:  "not both",
		{out, "", "hosts.ini"}: "-i doesn't go with -role",
	} {
		errOut.Reset()
		if code := runConvertRole(role, args[0], args[1], args[2], &errOut); code != 1 || !strings.Contains(errOut.String(), want) {
			t.Errorf("%v: exited %d: %s", args, code, errOut.String())
		}
	}
	// A role that isn't one, and an -out that can't be made, are errors.
	notRole := t.TempDir()
	errOut.Reset()
	if code := runConvertRole(notRole, filepath.Join(t.TempDir(), "c"), "", "", &errOut); code != 1 || !strings.HasPrefix(errOut.String(), "Error: ") {
		t.Errorf("not a role: exited %d: %s", code, errOut.String())
	}
	file := filepath.Join(t.TempDir(), "file")
	if err := os.WriteFile(file, nil, 0o644); err != nil {
		t.Fatal(err)
	}
	errOut.Reset()
	if code := runConvertRole(role, filepath.Join(file, "c"), "", "", &errOut); code != 1 || !strings.HasPrefix(errOut.String(), "Error: ") {
		t.Errorf("-out under a file: exited %d: %s", code, errOut.String())
	}
}

// A note on a converted step, such as the crontab entry Ansible left, is
// listed in the summary but doesn't make the run exit 3: convert writes it
// every time, so a CI loop could never reach zero.
func TestConvertListsNotesOnConvertedSteps(t *testing.T) {
	playbook := filepath.Join(t.TempDir(), "p.yml")
	if err := os.WriteFile(playbook, []byte("- hosts: all\n  tasks:\n    - name: Nightly\n      cron:\n        name: x\n        minute: \"0\"\n        job: \"true\"\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	var out, errOut bytes.Buffer
	code := runConvert(playbook, "", "", &out, &errOut)
	want := "Converted the 1 task.\n1 converted step has a note to act on once, also marked TODO(convert):\n  line 3, Nightly: Delete the \"#Ansible: x\" job Ansible left in the user's crontab, or it runs twice.\n"
	if code != 0 || errOut.String() != want {
		t.Fatalf("exited %d:\n%s", code, errOut.String())
	}
}

// A playbook's own text is printed in the summary, and must not be able to
// move the cursor or repaint the screen.
func TestConvertSummaryShowsControlCharactersAsEscapes(t *testing.T) {
	playbook := filepath.Join(t.TempDir(), "p.yml")
	if err := os.WriteFile(playbook, []byte("- hosts: all\n  tasks:\n    - name: \"a\\e[2Jb\\u202e\"\n      \"mod\\e[1A\": {}\n    - name: Nightly\n      cron: {name: \"x\\e[2K\", minute: \"0\", job: \"true\"}\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	var out, errOut bytes.Buffer
	if code := runConvert(playbook, "", "", &out, &errOut); code != 3 {
		t.Fatalf("exited %d:\n%s", code, errOut.String())
	}
	got := errOut.String()
	if strings.ContainsAny(got, "\x1b\u202e") {
		t.Fatalf("control characters reached the terminal: %q", got)
	}
	for _, want := range []string{`a\u001b[2Jb\u202e`, `mod\u001b[1A`, `x\u001b[2K`} {
		if !strings.Contains(got, want) {
			t.Errorf("%q isn't shown: %q", want, got)
		}
	}
}

// -out with roles: what this run didn't write must be easy to see, and the
// output file must not be written through a link.
func TestConvertOutKeepsWhatItDidNotWriteInSight(t *testing.T) {
	dir := t.TempDir()
	write := func(p, s string) {
		t.Helper()
		if err := os.MkdirAll(filepath.Dir(filepath.Join(dir, p)), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(dir, p), []byte(s), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	write("site.yml", "- hosts: all\n  roles: [web]\n")
	write("roles/web/tasks/main.yml", "- name: p\n  ping:\n")
	write("circuit-web/main.circuit.hcl", "# written by someone else\n")
	write("elsewhere.txt", "keep me\n")
	out := filepath.Join(dir, "site.tf")
	if err := os.Symlink(filepath.Join(dir, "elsewhere.txt"), out); err != nil {
		t.Skip(err)
	}
	var stdout, errOut bytes.Buffer
	if code := runConvert(filepath.Join(dir, "site.yml"), "", out, &stdout, &errOut); code != 0 {
		t.Fatalf("exited %d: %s", code, errOut.String())
	}
	if b, _ := os.ReadFile(filepath.Join(dir, "elsewhere.txt")); string(b) != "keep me\n" {
		t.Errorf("wrote through the link at -out: %q", b)
	}
	hcl, err := os.ReadFile(out)
	if err != nil {
		t.Fatal(err)
	}
	if st, err := os.Lstat(out); err != nil || st.Mode()&os.ModeSymlink != 0 {
		t.Errorf("-out is still a link: %v", err)
	}
	if !strings.Contains(string(hcl), "# TODO(convert): circuit-web already had files") || !strings.Contains(errOut.String(), "Kept circuit-web") {
		t.Errorf("nothing in the file says circuit-web wasn't written by this run:\n%s\n%s", hcl, errOut.String())
	}
	if b, _ := os.ReadFile(filepath.Join(dir, "circuit-web/main.circuit.hcl")); string(b) != "# written by someone else\n" {
		t.Errorf("the kept directory was changed: %q", b)
	}

	// A link where a role's directory would go is refused.
	if err := os.RemoveAll(filepath.Join(dir, "circuit-web")); err != nil {
		t.Fatal(err)
	}
	write("empty/.keep", "")
	if err := os.Remove(filepath.Join(dir, "empty/.keep")); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(filepath.Join(dir, "empty"), filepath.Join(dir, "circuit-web")); err != nil {
		t.Fatal(err)
	}
	errOut.Reset()
	if code := runConvert(filepath.Join(dir, "site.yml"), "", out, &stdout, &errOut); code != 1 || !strings.Contains(errOut.String(), "is a link") {
		t.Fatalf("exited %d: %s", code, errOut.String())
	}
	if entries, _ := os.ReadDir(filepath.Join(dir, "empty")); len(entries) != 0 {
		t.Errorf("wrote through the link: %v", entries)
	}
}
