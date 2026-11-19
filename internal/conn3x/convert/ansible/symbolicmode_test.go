// Copyright (c) The Conn3x Authors
// SPDX-License-Identifier: MPL-2.0

package ansible

import (
	"strings"
	"testing"
)

// A symbolic mode that sets all three classes with = never reads the file's
// current mode, so it has exactly one octal result and the task converts.
func TestConvertSymbolicMode(t *testing.T) {
	for mode, want := range map[string]string{
		"u=rw,g=r,o=r":       `mode = "0644"`,
		"o=r,u=rw,g=r":       `mode = "0644"`,
		"a=r":                `mode = "0444"`,
		"u=rwx,g=rx,o=":      `mode = "0750"`,
		"u=rws,g=rx,o=rx":    `mode = "4655"`,
		"u=rwxs,g=rx,o=rx":   `mode = "4755"`,
		"ug=rwxs,o=rx":       `mode = "6775"`,
		"a=rwxs":             `mode = "6777"`,
		"a=rwxt":             `mode = "1777"`,
		"ug=rwxt,o=rx":       `mode = "0775"`,
		"u=rwx,g=rwx,o=rwxt": `mode = "1777"`,
		"ug=rw,o=":           `mode = "0660"`,
		"a=":                 `mode = "0000"`,
	} {
		res := convertString(t, "- hosts: all\n  tasks:\n    - copy: {content: x, dest: /etc/app.conf, mode: '"+mode+"'}\n")
		if res.Converted != 1 || len(res.Review) != 0 {
			t.Errorf("%s: converted %d, review %+v", mode, res.Converted, res.Review)
			continue
		}
		// Attributes are column-aligned, so compare with the runs of
		// spaces collapsed.
		hcl := strings.Join(strings.Fields(string(res.HCL)), " ")
		if !strings.Contains(hcl, want) {
			t.Errorf("%s: missing %q:\n%s", mode, want, res.HCL)
		}
	}
}

// Anything that reads the file's current mode, the umask, or another class
// stays for review instead of being guessed.
func TestConvertSymbolicModeRefusals(t *testing.T) {
	for _, mode := range []string{
		"u+x",              // relative: depends on the current mode
		"u=rw,g=r",         // no o class: depends on the current mode
		"u=rwX,g=rX,o=rX",  // X: depends on the current mode
		"u=rw,g=r,o=u",     // copies a class: depends on the current mode
		"u=rw,u=r,g=r,o=r", // a class set twice
		"a=rw,u=r",         // a class set twice, through a
		"=rw",              // empty who: depends on the umask
		"u=rw,g=r,o=r ",    // trailing space, not a mode
		"u=rw,g=r,o=r,",    // empty clause
	} {
		res := convertString(t, "- hosts: all\n  tasks:\n    - copy: {content: x, dest: /etc/app.conf, mode: '"+mode+"'}\n")
		if res.Converted != 0 || len(res.Review) != 1 || !strings.Contains(res.Review[0].Reason, "is not an octal mode") {
			t.Errorf("%s: converted %d, review %+v", mode, res.Converted, res.Review)
		}
	}
}
