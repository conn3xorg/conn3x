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
		`\'`,
		`\\`,
		"two\nlines",
		`case ${SUDO_UID:-} in '' | *[!0-9]*) l=0 ;; esac`,
		"sudo -n -- /bin/sh -c " + Quote("printf '%s\\n' \"$x\" 'a\\'b'"),
	}
	for _, sh := range []string{"sh", "fish"} {
		if _, err := exec.LookPath(sh); err != nil {
			t.Logf("%s not installed", sh)
			continue
		}
		for _, s := range cases {
			out, err := exec.Command(sh, "-c", "printf %s "+LoginQuote(s)).Output()
			if err != nil || string(out) != s {
				t.Errorf("%s read %q as %q (%v)", sh, s, out, err)
			}
		}
	}
	if q := LoginQuote(`a'b\c`); strings.Contains(strings.ReplaceAll(q, `"\\"`, ""), `\`) {
		t.Errorf("a backslash outside double quotes: %s", q)
	}
}
