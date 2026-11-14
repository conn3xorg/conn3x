// Copyright (c) The Conn3x Authors
// SPDX-License-Identifier: MPL-2.0

//go:build e2e

package e2e

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// conn3x run takes hosts from an inventory by pattern, groups included,
// runs a command or a module on each, and writes no state.
func TestConn3xRun(t *testing.T) {
	web1, db1 := startHost(t, "rocky10"), startHost(t, "rocky10")
	knownFile := shareKey(t, web1, db1)
	w := &workdir{t: t, dir: t.TempDir()}
	inv := "[web]\nweb1 ansible_host=127.0.0.1 ansible_port=" + web1.port + "\n[db]\ndb1 ansible_host=127.0.0.1 ansible_port=" + db1.port + "\n[eu:children]\nweb\ndb\n[all:vars]\nansible_user=root\n"
	if err := os.WriteFile(filepath.Join(w.dir, "hosts.ini"), []byte(inv), 0o644); err != nil {
		t.Fatal(err)
	}
	run := func(args ...string) (string, int) {
		return w.conn3x(append([]string{"run", "-i", "hosts.ini", "-private-key-file", web1.keyFile, "-known-hosts-file", knownFile}, args...)...)
	}

	out, code := run("eu", "-a", "echo hi from $(cat /etc/hostname)")
	if code != 0 || !strings.Contains(out, "db1 | changed") || !strings.Contains(out, "web1 | changed") || strings.Count(out, "  hi from ") != 2 {
		t.Errorf("a command on group eu (exit %d):\n%s", code, out)
	}

	out, code = run("eu:&web", "-m", "file", "-a", "path=/tmp/motd content='hello there\n'")
	if code != 0 || !strings.Contains(out, "web1 | changed") || strings.Contains(out, "db1") {
		t.Errorf("a file on eu:&web (exit %d):\n%s", code, out)
	}
	if got := web1.exec("", "cat", "/tmp/motd"); got != "hello there\n" {
		t.Errorf("/tmp/motd = %q", got)
	}
	if out, _ := run("web", "-m", "file", "-a", "path=/tmp/motd content='hello there\n'"); !strings.Contains(out, "web1 | ok") {
		t.Errorf("the same file again should be ok:\n%s", out)
	}
	if out, _ := run("web", "-m", "file", "-a", "path=/tmp/motd content=bye", "-check"); !strings.Contains(out, "web1 | would change") {
		t.Errorf("-check:\n%s", out)
	}
	if got := web1.exec("", "cat", "/tmp/motd"); got != "hello there\n" {
		t.Errorf("-check changed the file: %q", got)
	}

	out, code = run("all:!db", "-a", "exit 3")
	if code != 2 || !strings.Contains(out, "web1 | failed") {
		t.Errorf("a failing command should exit 2 (exit %d):\n%s", code, out)
	}
	if out, code := run("nothing*", "-a", "true"); code != 1 || !strings.Contains(out, "matches no host") {
		t.Errorf("a pattern matching nothing (exit %d):\n%s", code, out)
	}
	if entries, _ := os.ReadDir(w.dir); len(entries) != 1 {
		t.Errorf("run should write nothing but leave hosts.ini: %v", entries)
	}
}

// conn3x run -task runs a task file's steps in order on each host, with
// params and the host's inventory variables, stopping a host at the first
// step that fails.
func TestConn3xRunTask(t *testing.T) {
	web1, db1 := startHost(t, "rocky10"), startHost(t, "rocky10")
	knownFile := shareKey(t, web1, db1)
	w := &workdir{t: t, dir: t.TempDir()}
	inv := "[web]\nweb1 ansible_host=127.0.0.1 ansible_port=" + web1.port + " role=front\n[db]\ndb1 ansible_host=127.0.0.1 ansible_port=" + db1.port + " role=data\n[all:vars]\nansible_user=root\n"
	task := `task "motd" {
  param "greeting" {}
  param "fail" { default = "false" }
  step "write" {
    file {
      path    = "/tmp/motd"
      content = "${param.greeting} from ${host.name}, ${host.vars.role}\n"
    }
  }
  step "maybe-fail" {
    command { command = param.fail == "true" ? "exit 4" : "true" }
  }
  step "after" {
    file {
      path    = "/tmp/after"
      content = "ran\n"
    }
  }
  step "cron" {
    crontab {
      user = "root"
      job {
        name     = "greet"
        schedule = "@daily"
        command  = "echo ${param.greeting}"
      }
    }
  }
}
`
	for name, body := range map[string]string{"hosts.ini": inv, "motd.task.hcl": task} {
		if err := os.WriteFile(filepath.Join(w.dir, name), []byte(body), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	run := func(args ...string) (string, int) {
		return w.conn3x(append([]string{"run", "-i", "hosts.ini", "-private-key-file", web1.keyFile, "-known-hosts-file", knownFile, "-task", "motd.task.hcl"}, args...)...)
	}

	for _, h := range []*host{web1, db1} {
		h.exec("", "sh", "-c", "dnf install -y -q cronie >/dev/null")
	}
	out, code := run("all", "-a", "greeting=hello")
	if code != 0 || !strings.Contains(out, "web1 | changed") || !strings.Contains(out, "db1 | changed") || !strings.Contains(out, "  write: changed") {
		t.Errorf("the task on all (exit %d):\n%s", code, out)
	}
	if got := web1.exec("", "cat", "/tmp/motd"); got != "hello from web1, front\n" {
		t.Errorf("web1 /tmp/motd = %q", got)
	}
	if got := db1.exec("", "cat", "/tmp/motd"); got != "hello from db1, data\n" {
		t.Errorf("db1 /tmp/motd = %q", got)
	}
	if got := web1.exec("", "crontab", "-l", "-u", "root"); !strings.Contains(got, "@daily echo hello") {
		t.Errorf("a nested job block should reach the crontab:\n%s", got)
	}

	db1.exec("", "rm", "-f", "/tmp/after")
	out, code = run("db", "-a", "greeting=hello fail=true")
	if code != 2 || !strings.Contains(out, "db1 | failed") || !strings.Contains(out, "maybe-fail: failed") || strings.Contains(out, "after:") {
		t.Errorf("a failing step should stop the host (exit %d):\n%s", code, out)
	}
	if got := db1.exec("", "sh", "-c", "test -e /tmp/after && echo there; true"); got != "" {
		t.Errorf("the step after a failure ran: %q", got)
	}

	if out, code := run("all"); code != 1 || !strings.Contains(out, "needs param greeting") {
		t.Errorf("a missing param (exit %d):\n%s", code, out)
	}
	if out, code := run("all", "-a", "greeting=x nope=1"); code != 1 || !strings.Contains(out, `no param "nope"`) {
		t.Errorf("an unknown param (exit %d):\n%s", code, out)
	}
}

// conn3x run -plan runs tasks in order, each on its own hosts, and stops
// at the first run where a host fails.
func TestConn3xRunPlan(t *testing.T) {
	web1, db1 := startHost(t, "rocky10"), startHost(t, "rocky10")
	knownFile := shareKey(t, web1, db1)
	w := &workdir{t: t, dir: t.TempDir()}
	files := map[string]string{
		"hosts.ini": "[web]\nweb1 ansible_host=127.0.0.1 ansible_port=" + web1.port + "\n[db]\ndb1 ansible_host=127.0.0.1 ansible_port=" + db1.port + "\n[all:vars]\nansible_user=root\n",
		"tasks/mark.task.hcl": `task "mark" {
  param "name" {}
  param "fail" { default = "false" }
  step "write" {
    file {
      path    = "/tmp/${param.name}"
      content = "${host.name}\n"
    }
  }
  step "maybe-fail" {
    command { command = param.fail == "true" ? "exit 4" : "true" }
  }
}
`,
		"release.plan.hcl": `plan "release" {
  param "version" {}
  param "fail_db" { default = "false" }
  run "migrate" {
    task   = "tasks/mark.task.hcl"
    hosts  = "db"
    params = { name = "migrated-${param.version}", fail = param.fail_db }
  }
  run "deploy" {
    task   = "tasks/mark.task.hcl"
    hosts  = "web"
    params = { name = "deployed-${param.version}" }
  }
}
`,
	}
	for name, body := range files {
		p := filepath.Join(w.dir, name)
		if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(p, []byte(body), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	run := func(args ...string) (string, int) {
		return w.conn3x(append([]string{"run", "-i", "hosts.ini", "-private-key-file", web1.keyFile, "-known-hosts-file", knownFile, "-plan", "release.plan.hcl"}, args...)...)
	}
	exists := func(h *host, path string) bool {
		return h.exec("", "sh", "-c", "test -e "+path+" && echo yes; true") == "yes\n"
	}

	out, code := run("all", "-a", "version=1")
	if code != 0 || strings.Index(out, "== migrate") > strings.Index(out, "== deploy") || !strings.Contains(out, "db1 | changed") || !strings.Contains(out, "web1 | changed") {
		t.Errorf("the plan (exit %d):\n%s", code, out)
	}
	if !exists(db1, "/tmp/migrated-1") || exists(web1, "/tmp/migrated-1") || !exists(web1, "/tmp/deployed-1") || exists(db1, "/tmp/deployed-1") {
		t.Errorf("each run should touch only its own hosts")
	}

	out, code = run("all", "-a", "version=2 fail_db=true")
	if code != 2 || !strings.Contains(out, "db1 | failed") || !strings.Contains(out, "== deploy: skipped, since migrate failed") || strings.Contains(out, "web1 |") {
		t.Errorf("a failed run should stop the plan (exit %d):\n%s", code, out)
	}
	if exists(web1, "/tmp/deployed-2") {
		t.Errorf("deploy ran after migrate failed")
	}

	if out, code := run("web", "-a", "version=3"); code != 0 || !strings.Contains(out, "== migrate: task mark, 0 host(s)") || !exists(web1, "/tmp/deployed-3") {
		t.Errorf("PATTERN should narrow every run (exit %d):\n%s", code, out)
	}
	if out, code := run("all"); code != 1 || !strings.Contains(out, "needs param version") {
		t.Errorf("a missing plan param (exit %d):\n%s", code, out)
	}
}
