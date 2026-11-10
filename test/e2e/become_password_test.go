// Copyright (c) The Conn3x Authors
// SPDX-License-Identifier: MPL-2.0

//go:build e2e

package e2e

import (
	"context"
	"os/exec"
	"strings"
	"testing"

	"github.com/opentofu/opentofu/internal/conn3x/transport/ssh"
)

// TestBecomeWithPassword runs commands through each image's own sudo with
// a password: the command's input arrives whole, a wrong password is an
// error, and no credentials stay cached for the login user afterwards.
func TestBecomeWithPassword(t *testing.T) {
	const input = "first line\nsecond line"
	for _, image := range linuxImages {
		t.Run(image, func(t *testing.T) {
			ctx := context.Background()
			h := startHost(t, image)
			addDeploy(h, "", "")
			sudoers := func(rule string) {
				h.exec("", "sh", "-c", `printf '%s\n' 'Defaults:deploy !pam_acct_mgmt, !pam_session' '`+rule+`' > /etc/sudoers.d/deploy && visudo -cq`)
			}
			run := func(password string) (ssh.Result, error) {
				b := &ssh.Become{Client: h.dial(t, "deploy"), Password: []byte(password)}
				return b.Run(ctx, "id -u; cat", []byte(input))
			}

			sudoers("deploy ALL=(ALL) ALL")
			// As in TestFileWithSudoPassword: rootless containers on some CI
			// runners can't run PAM's password helper, so sudo can't accept
			// even the right password there.
			if err := exec.Command("podman", "exec", h.container, "su", "deploy", "-c",
				"echo Deploy-Pass-123 | sudo -S -p '' -v").Run(); err != nil {
				t.Skip("this container can't verify sudo passwords (PAM's unix_chkpwd fails in rootless Podman); password sudo is covered on real hosts")
			}
			res, err := run("Deploy-Pass-123")
			if err != nil || string(res.Stdout) != "0\n"+input || len(res.Stderr) != 0 {
				t.Fatalf("with the password: stdout %q, stderr %q, err %v", res.Stdout, res.Stderr, err)
			}
			if cached, err := h.dial(t, "deploy").Run(ctx, "sudo -n true", nil); err != nil || cached.ExitCode == 0 {
				t.Fatalf("sudo -n after the run: exit %d, err %v; credentials stayed cached", cached.ExitCode, err)
			}
			if _, err := run("wrong"); err == nil || !strings.Contains(err.Error(), "incorrect password") {
				t.Fatalf("with a wrong password: %v", err)
			}

			// sudo asks for a password in general, as the probe finds, but
			// not for a shell. It never reads the password, so the command
			// must not get it as its first line of input.
			sudoers("deploy ALL=(ALL) NOPASSWD: /bin/sh, PASSWD: /bin/sh -c true")
			res, err = run("Deploy-Pass-123")
			if err != nil || string(res.Stdout) != "0\n"+input {
				t.Fatalf("when sudo doesn't prompt: stdout %q, stderr %q, err %v", res.Stdout, res.Stderr, err)
			}
		})
	}
}
