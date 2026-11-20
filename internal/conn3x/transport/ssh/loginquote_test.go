// Copyright (c) The Conn3x Authors
// SPDX-License-Identifier: MPL-2.0

package ssh

import (
	"os/exec"
	"strings"
	"testing"
)

// A login shell, POSIX or fish, reads LoginQuote's word as the string given,
// including when it holds a second layer of Quote, as a sudo line does.
func TestLoginQuote(t *testing.T) {
	cases := []string{
		"plain",
		"it's",
		`back\slash`,
		`a\\b`,
		`a\'b`,
		`end\`,
		`\'`,
		`\\`,
		"two\nlines",
		`case ${SUDO_UID:-} in '' | *[!0-9]*) l=0 ;; esac`,
		"sudo -n -- /bin/sh -c " + Quote("printf '%s\\n' \"$x\" 'a\\'b'"),
	}
	for _, sh := range []string{"sh", "fish", "tcsh"} {
		if _, err := exec.LookPath(sh); err != nil {
			t.Logf("%s not installed", sh)
			continue
		}
		for _, s := range cases {
			// tcsh refuses a line break inside quotes whatever the
			// quoting, and some versions expand ! even there (#1126).
			if sh == "tcsh" && strings.ContainsAny(s, "\n!") {
				continue
			}
			out, err := exec.Command(sh, "-c", "printf %s "+LoginQuote(s)).Output()
			if err != nil || string(out) != s {
				t.Errorf("%s read %q as %q (%v)", sh, s, out, err)
			}
		}
	}
	if q := LoginQuote(`a'b\c`); q != `'a'\''b'\\'c'` {
		t.Errorf("a quote and a backslash: %s", q)
	}
}

// csh and tcsh refuse the LC_ALL=C every Run starts with, and that reads
// as a csh login shell, not as the command failing.
func TestCshRefused(t *testing.T) {
	for _, s := range []string{
		"LC_ALL=C: Command not found.\n", "  LC_ALL=C: Command not found.", "Unmatched '''.\nUnmatched '''.\n", "Unmatched '''.\r\n\nUnmatched '''.\r\n", "Unmatched '''.\nUnmatched '''.\na: Undefined variable.\n",
		// tcsh's translations, as Foothills read them from tcsh 6.24.
		"LC_ALL=C: Befehl nicht gefunden.", "LC_ALL=C: Commande introuvable.", "LC_ALL=C: Comando no encontrado.", "LC_ALL=C: コマンドが見つかりません.",
		"Überflüssiges '''.", "''' sans correspondance.", "No se ha hallado correspondencia con '''.", "''' が対応しません.",
	} {
		if !cshRefused([]byte(s)) {
			t.Errorf("%q not read as csh", s)
		}
	}
	for _, s := range []string{"", "sh: 1: foo: not found", "make: LC_ALL=C: Command not found.", "echo '''\nother output", "other output\nUnmatched '''."} {
		if cshRefused([]byte(s)) {
			t.Errorf("%q read as csh", s)
		}
	}
	if _, err := exec.LookPath("tcsh"); err != nil {
		t.Skip("tcsh not installed")
	}
	cmd := exec.Command("tcsh", "-c", "LC_ALL=C exec /bin/sh -c "+LoginQuote(Prelude+"true"))
	var stderr strings.Builder
	cmd.Stderr = &stderr
	if err := cmd.Run(); err == nil || !cshRefused([]byte(stderr.String())) {
		t.Errorf("tcsh's own refusal, %v: %q", err, stderr.String())
	}
	// A script with a line break fails before LC_ALL=C is reached.
	cmd = exec.Command("tcsh", "-c", "LC_ALL=C exec /bin/sh -c "+LoginQuote(Prelude+"true\ntrue"))
	stderr.Reset()
	cmd.Stderr = &stderr
	if err := cmd.Run(); err == nil || !cshRefused([]byte(stderr.String())) {
		t.Errorf("tcsh's refusal of a line break, %v: %q", err, stderr.String())
	}
}
