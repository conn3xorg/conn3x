// Copyright (c) The Conn3x Authors
// SPDX-License-Identifier: MPL-2.0

//go:build e2e

package e2e

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

type pipVars struct{ Port, KeyFile, KnownHosts, Six string }
type pipGuardVars struct{ Port, KeyFile, KnownHosts, Venv, User string }

func startPythonHost(t *testing.T, image string) *host {
	t.Helper()
	h := startHost(t, image)
	install := "dnf -y -q install python3"
	if !rpmImage(image) {
		install = "apt-get update -qq && DEBIAN_FRONTEND=noninteractive apt-get install -y -q python3-venv"
	}
	h.exec("", "sh", "-c", install)
	return h
}

func pipVersion(h *host, venv, name string) string {
	out, _ := exec.Command("podman", "exec", h.container, venv+"/bin/python", "-m", "pip", "show", name).CombinedOutput()
	for _, l := range strings.Split(string(out), "\n") {
		if v, ok := strings.CutPrefix(l, "Version: "); ok {
			return v
		}
	}
	return ""
}

func TestPip(t *testing.T) {
	for _, image := range linuxImages {
		t.Run(image, func(t *testing.T) {
			h := startPythonHost(t, image)
			h.exec("", "useradd", "-m", "py")
			w := newWorkdir(t, "pip")
			w.writeAs("main.circuit.hcl", pipVars{h.port, h.keyFile, h.knownHosts, "1.16.0"})
			w.mustConn3x("init", "-no-color")
			w.mustConn3x("apply", "-auto-approve", "-no-color")

			if got := pipVersion(h, "/opt/rootvenv", "six"); got != "1.16.0" {
				t.Fatalf("six = %q", got)
			}
			if got := pipVersion(h, "/home/py/venv", "iniconfig"); got != "2.0.0" && got != "2.0" {
				t.Fatalf("iniconfig = %q", got)
			}
			// What a step builds as a user belongs to them, not to root.
			if out := h.exec("", "find", "/home/py/venv", "!", "-user", "py"); out != "" {
				t.Fatalf("not the user's:\n%s", out)
			}

			// Pinned, unpinned, latest and absent all settle, including a
			// pin of 2.0 for a package that reports another spelling of it.
			if out := w.mustConn3x("plan", "-no-color"); !strings.Contains(out, "No changes.") {
				t.Fatalf("plan after apply is not empty:\n%s", out)
			}
			if out, code := w.conn3x("drift", "-no-color"); code != 0 || !strings.Contains(out, "No drift") {
				t.Fatalf("drift right after apply exited %d:\n%s", code, out)
			}

			// Someone moves a pin by hand, in each venv.
			h.exec("", "/opt/rootvenv/bin/python", "-m", "pip", "install", "-q", "six==1.15.0")
			out, code := w.conn3x("drift", "-no-color")
			if code != 2 || !strings.Contains(out, `conn3x_pip.py__root_pin["box"]`) {
				t.Fatalf("drift exited %d:\n%s", code, out)
			}
			h.exec("", "runuser", "-u", "py", "--", "/home/py/venv/bin/python", "-m", "pip", "uninstall", "-q", "-y", "iniconfig")
			out, code = w.conn3x("drift", "-no-color")
			if code != 2 || !strings.Contains(out, `conn3x_pip.py__user_pin["box"]`) {
				t.Fatalf("drift exited %d:\n%s", code, out)
			}
			// The state = "absent" step sees what someone added.
			h.exec("", "/opt/rootvenv/bin/python", "-m", "pip", "install", "-q", "idna")
			w.mustConn3x("apply", "-auto-approve", "-no-color")
			if got := pipVersion(h, "/opt/rootvenv", "six"); got != "1.16.0" {
				t.Fatalf("six after repair = %q", got)
			}
			if got := pipVersion(h, "/opt/rootvenv", "idna"); got != "" {
				t.Fatalf("idna after repair = %q", got)
			}
			if out := w.mustConn3x("plan", "-no-color"); !strings.Contains(out, "No changes.") {
				t.Fatalf("plan after repair is not empty:\n%s", out)
			}

			// Changing the pin goes down a version too.
			w.writeAs("main.circuit.hcl", pipVars{h.port, h.keyFile, h.knownHosts, "1.15.0"})
			w.mustConn3x("apply", "-auto-approve", "-no-color")
			if got := pipVersion(h, "/opt/rootvenv", "six"); got != "1.15.0" {
				t.Fatalf("six after a lower pin = %q", got)
			}

			// A venv whose python broke gets rebuilt.
			h.exec("", "rm", "-f", "/home/py/venv/bin/python")
			w.mustConn3x("apply", "-auto-approve", "-no-color")
			if got := pipVersion(h, "/home/py/venv", "iniconfig"); got == "" {
				t.Fatal("iniconfig missing after rebuilding the venv")
			}
		})
	}
}

// Connected as root, a step never runs code a user could have planted in a
// venv: without user it refuses, and with user the code runs as that user.
func TestPipWontRunAnotherUsersCodeAsRoot(t *testing.T) {
	for _, image := range linuxImages {
		t.Run(image, func(t *testing.T) {
			h := startPythonHost(t, image)
			// A venv whose python runs whatever its owner wrote.
			evil := "#!/bin/sh\nid -u > /tmp/ran-as\nexit 1\n"
			h.exec(evil, "sh", "-c", "useradd -m mal && runuser -u mal -- mkdir -p /home/mal/venv/bin && cat > /home/mal/venv/bin/python && chown mal /home/mal/venv/bin/python && chmod 755 /home/mal/venv/bin/python")
			w := newWorkdir(t, "pip_guard")
			w.writeAs("main.circuit.hcl", pipGuardVars{h.port, h.keyFile, h.knownHosts, "/home/mal/venv", ""})
			w.mustConn3x("init", "-no-color")
			out, code := w.conn3x("apply", "-auto-approve", "-no-color")
			if code == 0 || !strings.Contains(strings.Join(strings.Fields(out), " "), "set user") {
				t.Fatalf("apply into another user's venv as root exited %d:\n%s", code, out)
			}
			if _, err := exec.Command("podman", "exec", h.container, "test", "-e", "/tmp/ran-as").CombinedOutput(); err == nil {
				t.Fatal("the planted python ran")
			}

			// A venv reached through a root-owned link is judged by where it leads.
			h.exec("", "ln", "-s", "/home/mal/venv", "/opt/link")
			w2 := newWorkdir(t, "pip_guard")
			w2.writeAs("main.circuit.hcl", pipGuardVars{h.port, h.keyFile, h.knownHosts, "/opt/link", ""})
			w2.mustConn3x("init", "-no-color")
			if out, code := w2.conn3x("apply", "-auto-approve", "-no-color"); code == 0 {
				t.Fatalf("apply through a link exited 0:\n%s", out)
			}

			// A directory anyone can write to above the venv.
			h.exec("", "mkdir", "-m", "0777", "/opt/open")
			w3 := newWorkdir(t, "pip_guard")
			w3.writeAs("main.circuit.hcl", pipGuardVars{h.port, h.keyFile, h.knownHosts, "/opt/open/venv", ""})
			w3.mustConn3x("init", "-no-color")
			if out, code := w3.conn3x("apply", "-auto-approve", "-no-color"); code == 0 || !strings.Contains(out, "written by other users") {
				t.Fatalf("apply under a 0777 directory exited %d:\n%s", code, out)
			}

			// With user set, the same planted python runs as that user, and
			// gets nothing it didn't have.
			w4 := newWorkdir(t, "pip_guard")
			w4.writeAs("main.circuit.hcl", pipGuardVars{h.port, h.keyFile, h.knownHosts, "/home/mal/venv", "mal"})
			w4.mustConn3x("init", "-no-color")
			w4.conn3x("apply", "-auto-approve", "-no-color")
			uid := strings.TrimSpace(h.exec("", "id", "-u", "mal"))
			if got := strings.TrimSpace(h.exec("", "cat", "/tmp/ran-as")); got != uid {
				t.Fatalf("planted python ran as uid %s, want %s", got, uid)
			}
		})
	}
}

func TestConvertAnsiblePipThenApply(t *testing.T) {
	for _, image := range linuxImages {
		t.Run(image, func(t *testing.T) {
			h := startPythonHost(t, image)
			w := newWorkdir(t, "pip_convert")
			w.writeAs("play.yml", nil)
			out, code := w.conn3x("convert", "ansible", "-out", "play.tf", "play.yml")
			if code != 3 || !strings.Contains(out, "Converted 2 tasks") || !strings.Contains(out, "requirements file") {
				t.Fatalf("convert exited %d:\n%s", code, out)
			}
			tf, err := os.ReadFile(filepath.Join(w.dir, "play.tf"))
			if err != nil {
				t.Fatal(err)
			}
			patched := strings.Replace(string(tf), "private_key_file = var.ssh_private_key_file",
				fmt.Sprintf("private_key_file = var.ssh_private_key_file\n    port = %s\n    known_hosts_file = %q", h.port, h.knownHosts), 1)
			vars := fmt.Sprintf("box_hosts = { box = \"127.0.0.1\" }\nssh_user = \"root\"\nssh_private_key_file = %q\n", h.keyFile)
			for name, content := range map[string]string{"play.tf": patched, "terraform.tfvars": vars} {
				if err := os.WriteFile(filepath.Join(w.dir, name), []byte(content), 0o644); err != nil {
					t.Fatal(err)
				}
			}
			w.mustConn3x("init", "-no-color")
			w.mustConn3x("apply", "-auto-approve", "-no-color")
			if got := pipVersion(h, "/opt/conv", "six") + " " + pipVersion(h, "/opt/conv", "iniconfig"); got != "1.16.0 2.0.0" {
				t.Fatalf("converted pins = %q", got)
			}
			if out := w.mustConn3x("plan", "-no-color"); !strings.Contains(out, "No changes.") {
				t.Fatalf("plan after apply:\n%s", out)
			}
		})
	}
}
