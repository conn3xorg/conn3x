// Copyright (c) The Conn3x Authors
// SPDX-License-Identifier: MPL-2.0

package facts

import (
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"runtime"
	"testing"
)

func TestParse(t *testing.T) {
	out := `id=rocky
version=10.0
codename=
like=rhel centos fedora
arch=x86_64
cpus=2
memory_kb=2013564
ipv4=203.0.113.10
`
	got, err := parse(out)
	if err != nil {
		t.Fatal(err)
	}
	want := Facts{Family: "redhat", ID: "rocky", Version: "10.0", Arch: "x86_64", CPUs: 2, MemoryMB: 1966, IPv4: "203.0.113.10"}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("got %+v\nwant %+v", got, want)
	}

	deb, err := parse("id=ubuntu\nversion=24.04\ncodename=noble\nservice_manager=systemd\nlike=debian\narch=aarch64\ncpus=4\nmemory_kb=4096000\nipv4=\n")
	if err != nil || deb.Family != "debian" || deb.Codename != "noble" || deb.ServiceManager != "systemd" || deb.IPv4 != "" {
		t.Fatalf("got %+v, %v", deb, err)
	}
	// PID 1 can be called anything; a name that isn't a plain word is "".
	if odd, err := parse("id=debian\nservice_manager=my init;id\narch=x86_64\ncpus=1\nmemory_kb=1024\n"); err != nil || odd.ServiceManager != "" {
		t.Fatalf("got %+v, %v", odd, err)
	}
	if _, err := parse("id=alpine\nversion=3.20\narch=x86_64\ncpus=1\nmemory_kb=1\n"); err == nil {
		t.Fatal("accepted an unsupported family")
	}
	if _, err := parse("id=rocky\ncpus=lots\n"); err == nil {
		t.Fatal("accepted a non-numeric CPU count")
	}
}

// A circuit can put one host's fact into a command for another host, so a
// fact has to be the plain word it claims to be.
func TestParseRefusesFactsThatAreNotPlainWords(t *testing.T) {
	good := map[string]string{"id": "rocky", "version": "10.0", "codename": "", "arch": "x86_64", "ipv4": "203.0.113.10"}
	for name, c := range map[string]struct{ key, value string }{
		"shell in the OS id":      {"id", "rocky; touch /tmp/x"},
		"upper case OS id":        {"id", "Rocky"},
		"substitution in version": {"version", "10.0$(id)"},
		"quote in version":        {"version", `10"`},
		"shell in the codename":   {"codename", "noble;id"},
		"space in arch":           {"arch", "x86_64 -o"},
		"empty arch":              {"arch", ""},
		"host name for ipv4":      {"ipv4", "example.com"},
		"ipv4 with a command":     {"ipv4", "203.0.113.10;id"},
		"ipv6 for ipv4":           {"ipv4", "2001:db8::1"},
		"escape sequence":         {"version", "10\x1b[2J"},
	} {
		out := "like=rhel\ncpus=1\nmemory_kb=1024\n"
		for k, v := range good {
			if k == c.key {
				v = c.value
			}
			out += k + "=" + v + "\n"
		}
		if f, err := parse(out); err == nil {
			t.Errorf("%s: accepted %+v", name, f)
		}
	}
	// Debian testing has no VERSION_ID.
	if _, err := parse("id=debian\nversion=\narch=aarch64\ncpus=1\nmemory_kb=1024\nipv4=\n"); err != nil {
		t.Errorf("empty version: %v", err)
	}
}

// The codename comes from os-release as Ansible reads it: VERSION_CODENAME,
// UBUNTU_CODENAME when that isn't set, and empty when neither is.
func TestCodenameLine(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("needs sh")
	}
	for name, c := range map[string]struct{ osRelease, want string }{
		"debian 13":            {"ID=debian\nVERSION_ID=\"13\"\nVERSION_CODENAME=trixie\n", "trixie"},
		"ubuntu 24.04":         {"ID=ubuntu\nVERSION_ID=\"24.04\"\nVERSION_CODENAME=noble\nUBUNTU_CODENAME=noble\n", "noble"},
		"only UBUNTU_CODENAME": {"ID=ubuntu\nUBUNTU_CODENAME=xenial\n", "xenial"},
		"rocky 10":             {"ID=\"rocky\"\nVERSION=\"10.0 (Red Quartz)\"\nVERSION_ID=\"10.0\"\n", ""},
		"set empty":            {"ID=fedora\nVERSION_CODENAME=\"\"\nUBUNTU_CODENAME=odd\n", ""},
	} {
		f := filepath.Join(t.TempDir(), "os-release")
		if err := os.WriteFile(f, []byte(c.osRelease), 0o600); err != nil {
			t.Fatal(err)
		}
		out, err := exec.Command("sh", "-c", ". \"$1\"\n"+codenameLine, "sh", f).Output()
		if got := string(out); err != nil || got != "codename="+c.want+"\n" {
			t.Errorf("%s: %q, %v", name, got, err)
		}
	}
}

// The service manager follows Ansible's service_mgr.py on Linux, against a
// fake root and a PATH with or without systemctl.
func TestServiceManager(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("needs sh")
	}
	for name, c := range map[string]struct {
		comm      string // "" for no /proc/1/comm
		systemctl bool
		dir, init string // a directory to make, and where /sbin/init links
		want      string
	}{
		"systemd as pid 1":          {comm: "systemd", want: "systemd"},
		"init, booted with systemd": {comm: "init", systemctl: true, dir: "/run/systemd/system", want: "systemd"},
		"init, no systemd":          {comm: "init", systemctl: true, want: ""},
		"booted, no systemctl":      {comm: "init", dir: "/run/systemd/system", want: ""},
		"bash in a container":       {comm: "bash", want: ""},
		"bash, init is systemd":     {comm: "bash", systemctl: true, init: "/lib/systemd/systemd", want: "systemd"},
		"runit renamed":             {comm: "runit-init", want: "runit"},
		"another init":              {comm: "tini", want: "tini"},
		"no proc":                   {systemctl: true, dir: "/run/systemd/system", want: "systemd"},
	} {
		root, bin := t.TempDir(), t.TempDir()
		for _, tool := range []string{"cat", "readlink"} {
			p, err := exec.LookPath(tool)
			if err != nil {
				t.Fatal(err)
			}
			if err := os.Symlink(p, filepath.Join(bin, tool)); err != nil {
				t.Fatal(err)
			}
		}
		if c.systemctl {
			if err := os.WriteFile(filepath.Join(bin, "systemctl"), []byte("#!/bin/sh\n"), 0o700); err != nil {
				t.Fatal(err)
			}
		}
		if c.comm != "" {
			mustWrite(t, filepath.Join(root, "proc/1/comm"), c.comm+"\n")
		}
		if c.dir != "" {
			if err := os.MkdirAll(filepath.Join(root, c.dir), 0o700); err != nil {
				t.Fatal(err)
			}
		}
		if c.init != "" {
			if err := os.MkdirAll(filepath.Join(root, "sbin"), 0o700); err != nil {
				t.Fatal(err)
			}
			if err := os.Symlink(c.init, filepath.Join(root, "sbin/init")); err != nil {
				t.Fatal(err)
			}
		}
		cmd := exec.Command("/bin/sh", "-c", serviceManager+`echo "service_manager=$(service_manager "$1")"`, "sh", root)
		cmd.Env = []string{"PATH=" + bin}
		out, err := cmd.Output()
		if got := string(out); err != nil || got != "service_manager="+c.want+"\n" {
			t.Errorf("%s: %q, %v", name, got, err)
		}
	}
}

func mustWrite(t *testing.T, path, content string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
}
