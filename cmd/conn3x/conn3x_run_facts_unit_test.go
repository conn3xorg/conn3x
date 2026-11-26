// Copyright (c) The Conn3x Authors
// SPDX-License-Identifier: MPL-2.0

package main

import (
	"encoding/json"
	"strings"
	"testing"
)

// osRelease answers the facts script as a host with this os-release would.
// Ubuntu has a codename; Rocky doesn't.
func osRelease(id, version, like string) func(string, []byte) (string, int) {
	codename := map[string]string{"ubuntu": "noble"}[id]
	return func(cmd string, _ []byte) (string, int) {
		if strings.Contains(cmd, "/etc/os-release") {
			return "id=" + id + "\nversion=" + version + "\ncodename=" + codename + "\nservice_manager=systemd\nlike=" + like + "\narch=x86_64\ncpus=2\nmemory_kb=4046848\nipv4=10.0.0.5\n", 0
		}
		return "", 0
	}
}

func TestRunFacts(t *testing.T) {
	inv := brInventory(t, osRelease("rocky", "10.0", "rhel centos fedora"), osRelease("ubuntu", "24.04", "debian"))

	code, out, errOut := brRun(runOptions{inventory: inv, module: "facts", forks: 2})
	want := "web1 | os_family=redhat os_id=rocky os_version=10.0 os_codename=\"\" service_manager=systemd arch=x86_64 cpus=2 memory_mb=3952 ipv4=10.0.0.5\n" +
		"web2 | os_family=debian os_id=ubuntu os_version=24.04 os_codename=noble service_manager=systemd arch=x86_64 cpus=2 memory_mb=3952 ipv4=10.0.0.5\n"
	if code != 0 || out != want {
		t.Fatalf("exit %d:\n%s\nwant:\n%s\nstderr: %s", code, out, want, errOut)
	}

	code, out, _ = brRun(runOptions{inventory: inv, module: "facts", args: "filter=os_*,arch", pattern: "web2"})
	if want := "web2 | os_family=debian os_id=ubuntu os_version=24.04 os_codename=noble arch=x86_64\n"; code != 0 || out != want {
		t.Errorf("filtered: exit %d, %q", code, out)
	}

	// Facts change nothing, so -check reads them all the same.
	if code, out, _ = brRun(runOptions{inventory: inv, module: "facts", args: "filter=os_id", pattern: "web1", check: true}); code != 0 || out != "web1 | os_id=rocky\n" {
		t.Errorf("-check: exit %d, %q", code, out)
	}

	code, out, _ = brRun(runOptions{inventory: inv, module: "facts", pattern: "web1", json: true})
	var got struct {
		Host, Status string
		Facts        map[string]any
	}
	if err := json.Unmarshal([]byte(out), &got); code != 0 || err != nil || got.Host != "web1" || got.Status != "ok" || got.Facts["os_family"] != "redhat" || got.Facts["cpus"] != float64(2) {
		t.Errorf("-json: exit %d, %v, %+v:\n%s", code, err, got, out)
	}
}

func TestRunFactsRefuses(t *testing.T) {
	inv := brInventory(t, osRelease("rocky", "10.0", "rhel"))
	for args, want := range map[string]string{
		"path=/etc":   "-m facts takes only filter",
		"filter=[":    "isn't a glob",
		"filter='a b": "-a:",
	} {
		if code, _, errOut := brRun(runOptions{inventory: inv, module: "facts", args: args}); code != 1 || !strings.Contains(errOut, want) {
			t.Errorf("-a %s: exit %d, %q", args, code, errOut)
		}
	}
	for _, m := range []string{"setup", "gather_facts"} {
		if code, _, errOut := brRun(runOptions{inventory: inv, module: m}); code != 1 || !strings.Contains(errOut, "it's -m facts") {
			t.Errorf("-m %s: exit %d, %q", m, code, errOut)
		}
	}
}
