// Copyright (c) The Conn3x Authors
// SPDX-License-Identifier: MPL-2.0

package confirm

import (
	"context"
	"strings"
	"testing"
	"time"
)

// The revert puts each file back from its copy, or removes it when there
// was none, runs the undo commands and the reload, and cleans up after
// itself. Paths are quoted for the shell.
func TestScript(t *testing.T) {
	g := Guard{ID: "abc", Files: []string{"/etc/ssh/sshd_config.d/99 x.conf"}, Undo: []string{"ufw delete allow 22"}, Reload: "systemctl reload sshd", After: time.Minute}
	s := g.Script()
	for _, want := range []string{
		`d='/var/lib/conn3x/revert/abc'`,
		`if [ -e "$d/0.absent" ]; then rm -f -- '/etc/ssh/sshd_config.d/99 x.conf'; else cp -a -- "$d/0" '/etc/ssh/sshd_config.d/99 x.conf'; fi`,
		"ufw delete allow 22 || true",
		"systemctl reload sshd || true",
		`rm -rf -- "$d"`,
	} {
		if !strings.Contains(s, want) {
			t.Errorf("script lacks %q:\n%s", want, s)
		}
	}
	if strings.Index(s, "ufw delete") > strings.Index(s, "systemctl reload") {
		t.Error("the undo commands should run before the reload")
	}
}

func TestArmNeedsAnIDAndATime(t *testing.T) {
	if err := Arm(context.Background(), nil, Guard{}); err == nil {
		t.Fatal("an empty guard should be refused")
	}
}
