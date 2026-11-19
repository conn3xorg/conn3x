// Copyright (c) The Conn3x Authors
// SPDX-License-Identifier: MPL-2.0

package e2e

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

// sshd hands every command to the login shell first. With fish there, the
// reads that quote a script twice, as sudo does, reported "would change" for
// what matched (#1124).
func TestFishLoginShell(t *testing.T) {
	h := startHost(t, "debian13")
	if err := exec.Command("podman", "exec", h.container, "sh", "-c",
		"apt-get -qq update && apt-get -qq install -y fish").Run(); err != nil {
		t.Skipf("can't install fish in the container: %v", err)
	}
	// sshd skips PAM so a non-root login works in rootless containers, and a
	// password keeps the account from counting as locked.
	h.exec("", "sh", "-c", `useradd -m -s /usr/bin/fish deploy && echo 'deploy:Deploy-Pass-123' | chpasswd &&
echo 'deploy ALL=(ALL) NOPASSWD: ALL' > /etc/sudoers.d/deploy && chmod 440 /etc/sudoers.d/deploy &&
mkdir -p -m 700 /home/deploy/.ssh && cp /root/.ssh/authorized_keys /home/deploy/.ssh/ &&
chown -R deploy:deploy /home/deploy/.ssh &&
echo 'UsePAM no' > /etc/ssh/sshd_config.d/00-conn3x-test.conf && systemctl restart ssh`)

	w := &workdir{t: t, dir: t.TempDir()}
	inv := "fish1 ansible_host=127.0.0.1 ansible_port=" + h.port + " ansible_user=deploy\n"
	if err := os.WriteFile(filepath.Join(w.dir, "hosts.ini"), []byte(inv), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(w.dir, "hostname"), []byte(h.exec("", "cat", "/etc/hostname")), 0o644); err != nil {
		t.Fatal(err)
	}
	run := func(args ...string) string {
		out, _ := w.conn3x(append([]string{"run", "-i", "hosts.ini", "-private-key-file", h.keyFile, "-known-hosts-file", h.knownHosts, "fish1"}, args...)...)
		return out
	}

	if out := run("-a", "echo $FISH_VERSION; ps -o comm= -p $PPID"); !strings.Contains(out, "fish") {
		t.Fatalf("the login shell isn't fish:\n%s", out)
	}
	for name, args := range map[string][]string{
		"file":            {"-m", "file", "-a", "path=/etc/hostname src=hostname owner=root group=root mode=0644", "-check"},
		"file, become":    {"-become", "-m", "file", "-a", "path=/etc/hostname src=hostname owner=root group=root mode=0644", "-check"},
		"directory":       {"-m", "directory", "-a", "path=/etc/ssh owner=root group=root mode=0755", "-check"},
		"package, become": {"-become", "-m", "package", "-a", "name=openssh-server", "-check"},
	} {
		if out := run(args...); !strings.Contains(out, "fish1 | ok") {
			t.Errorf("%s, which matches, under fish:\n%s", name, out)
		}
	}
	// A real change still shows as one.
	if out := run("-become", "-m", "file", "-a", "path=/etc/hostname content=other", "-check"); !strings.Contains(out, "fish1 | would change") {
		t.Errorf("different content under fish:\n%s", out)
	}
}
