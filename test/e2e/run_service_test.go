// Copyright (c) The Conn3x Authors
// SPDX-License-Identifier: MPL-2.0

//go:build e2e

package e2e

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// conn3x run -m service with state=restarted restarts the unit every time,
// and state=reloaded reloads it, as ansible -m service does.
func TestRunServiceRestart(t *testing.T) {
	web1 := startHost(t, "rocky10")
	w := &workdir{t: t, dir: t.TempDir()}
	inv := "[web]\nweb1 ansible_host=127.0.0.1 ansible_port=" + web1.port + " ansible_user=root\n"
	if err := os.WriteFile(filepath.Join(w.dir, "hosts.ini"), []byte(inv), 0o644); err != nil {
		t.Fatal(err)
	}
	web1.exec("[Unit]\nDescription=demo\n[Service]\nExecStart=/bin/sleep infinity\nExecReload=/bin/touch /tmp/conn3x-reloaded\n",
		"sh", "-c", "cat > /etc/systemd/system/conn3x-demo.service && systemctl daemon-reload && systemctl start conn3x-demo")
	started := func() string {
		return strings.TrimSpace(web1.exec("", "systemctl", "show", "-p", "ExecMainStartTimestampMonotonic", "--value", "conn3x-demo"))
	}
	run := func(args ...string) (string, int) {
		return w.conn3x(append([]string{"run", "-i", "hosts.ini", "-private-key-file", web1.keyFile, "-known-hosts-file", web1.knownHosts}, args...)...)
	}

	before := started()
	for range 2 {
		time.Sleep(100 * time.Millisecond)
		if out, code := run("web", "-m", "service", "-a", "name=conn3x-demo state=restarted"); code != 0 || !strings.Contains(out, "web1 | changed") {
			t.Fatalf("restart (exit %d):\n%s", code, out)
		}
		if now := started(); now == before {
			t.Fatalf("the unit wasn't restarted: started at %s both times", now)
		} else {
			before = now
		}
	}
	if out, code := run("web", "-m", "service", "-a", "name=conn3x-demo state=reloaded"); code != 0 || !strings.Contains(out, "web1 | changed") {
		t.Fatalf("reload (exit %d):\n%s", code, out)
	}
	if got := strings.TrimSpace(web1.exec("", "sh", "-c", "test -e /tmp/conn3x-reloaded && echo yes || echo no")); got != "yes" {
		t.Error("the unit wasn't reloaded")
	}
	if out, code := run("web", "-m", "service", "-a", "name=conn3x-demo state=restarted enabled=true"); code == 0 || !strings.Contains(out, "can't go with enabled") {
		t.Errorf("restarted with enabled (exit %d):\n%s", code, out)
	}
}
