// Copyright (c) The Conn3x Authors
// SPDX-License-Identifier: MPL-2.0

//go:build e2e

package e2e

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// conn3x run -m facts reads each host's facts, as ansible -m setup does,
// and changes nothing.
func TestConn3xRunFacts(t *testing.T) {
	rocky, ubuntu := startHost(t, "rocky10"), startHost(t, "ubuntu2404")
	knownFile := shareKey(t, rocky, ubuntu)
	w := &workdir{t: t, dir: t.TempDir()}
	inv := "rocky ansible_host=127.0.0.1 ansible_port=" + rocky.port + "\nubuntu ansible_host=127.0.0.1 ansible_port=" + ubuntu.port + "\n[all:vars]\nansible_user=root\n"
	if err := os.WriteFile(filepath.Join(w.dir, "hosts.ini"), []byte(inv), 0o644); err != nil {
		t.Fatal(err)
	}
	run := func(args ...string) (string, int) {
		return w.conn3x(append([]string{"run", "-i", "hosts.ini", "-private-key-file", rocky.keyFile, "-known-hosts-file", knownFile}, args...)...)
	}

	out, code := run("all", "-m", "facts")
	if code != 0 || !strings.Contains(out, "rocky | os_family=redhat os_id=rocky os_version=10") || !strings.Contains(out, "ubuntu | os_family=debian os_id=ubuntu os_version=24.04") {
		t.Fatalf("exit %d:\n%s", code, out)
	}
	for _, f := range []string{"arch=", "cpus=", "memory_mb="} {
		if strings.Count(out, f) != 2 {
			t.Errorf("not two %s:\n%s", f, out)
		}
	}

	out, code = run("ubuntu", "-m", "facts", "-a", "filter=os_family", "-json")
	var got struct {
		Host  string
		Facts map[string]any
	}
	if err := json.Unmarshal([]byte(strings.TrimSpace(out)), &got); code != 0 || err != nil || got.Host != "ubuntu" || len(got.Facts) != 1 || got.Facts["os_family"] != "debian" {
		t.Errorf("-json with a filter: exit %d, %v, %+v:\n%s", code, err, got, out)
	}
}
