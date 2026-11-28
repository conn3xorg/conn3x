// Copyright (c) The Conn3x Authors
// SPDX-License-Identifier: MPL-2.0

//go:build e2e

package e2e

import (
	"regexp"
	"strings"
	"testing"
)

type onlyIfVars struct {
	Port, KeyFile, KnownHosts string
	Content                   string
	Absent                    bool
}

// A probe declared after a step that changes the host reads during the
// apply, after that step, and steps with only_if branch on what it found.
func TestOnlyIfReadsAfterEarlierSteps(t *testing.T) {
	h := startHost(t, "debian13")
	w := newWorkdir(t, "only_if")
	vars := onlyIfVars{Port: h.port, KeyFile: h.keyFile, KnownHosts: h.knownHosts, Content: "v1"}
	count := func(path string) int {
		return strings.Count(h.exec("", "sh", "-c", "cat "+path+" 2>/dev/null || true"), "\n")
	}
	starts := func() int { return count("/var/log/conn3x-demo.starts") }
	hasFallback := func() bool {
		return strings.TrimSpace(h.exec("", "sh", "-c", "test -f /etc/app.fallback && echo yes || echo no")) == "yes"
	}
	clean := func(when string) {
		t.Helper()
		if out := w.mustConn3x("plan", "-no-color"); !strings.Contains(out, "No changes.") {
			t.Fatalf("plan %s isn't clean:\n%s", when, out)
		}
	}

	// First apply: no /etc/app.conf until conf writes it.
	w.writeAs("main.circuit.hcl", vars)
	w.mustConn3x("init", "-no-color")
	out := w.mustConn3x("plan", "-no-color")
	for _, want := range []string{
		`data\.conn3x_command\.app__conf_there\["box"\] will be read during apply`,
		`(?s)conn3x_command\.app__init\["box"\] will be created.*only_if +=.*skipped +=`,
		`skipped +=\s*\(known after apply\)`,
	} {
		if !regexp.MustCompile(want).MatchString(out) {
			t.Fatalf("plan doesn't show %s:\n%s", want, out)
		}
	}
	// OpenTofu lists every write-only argument of a step being created, so
	// steps without only_if show it too; only gated ones show skipped.
	if n := strings.Count(out, "(known after apply)\n"); !strings.Contains(out, "skipped") || n == 0 {
		t.Fatalf("no gated step shows a pending skipped:\n%s", out)
	}
	out = w.mustConn3x("apply", "-auto-approve", "-no-color")
	if strings.Index(out, `conn3x_file.app__conf["box"]: Creation complete`) > strings.Index(out, `data.conn3x_command.app__conf_there["box"]: Read complete`) {
		t.Fatalf("the probe read before conf wrote the file:\n%s", out)
	}
	if count("/var/log/app.init") != 1 {
		t.Fatalf("init, gated on the file being there, didn't run once:\n%s", out)
	}
	if hasFallback() {
		t.Fatal("fallback, gated on the file missing, ran")
	}
	if starts() != 1 {
		t.Fatalf("the skipped step's handler restarted the service (%d starts)", starts())
	}
	if state := w.mustConn3x("state", "show", `conn3x_file.app__fallback["box"]`); !strings.Contains(state, "skipped") || !strings.Contains(state, "true") {
		t.Fatalf("fallback isn't recorded as skipped:\n%s", state)
	}
	clean("after the first apply")

	// conf changes, the probe's answer doesn't: init doesn't run again and
	// the handler doesn't fire.
	vars.Content = "v2"
	w.writeAs("main.circuit.hcl", vars)
	w.mustConn3x("apply", "-auto-approve", "-no-color")
	if count("/var/log/app.init") != 1 || hasFallback() || starts() != 1 {
		t.Fatalf("same answer: init ran %d times, fallback %v, %d starts", count("/var/log/app.init"), hasFallback(), starts())
	}
	clean("after an apply with the same answer")

	// conf removes the file: the probe's answer flips on this apply.
	vars.Absent = true
	w.writeAs("main.circuit.hcl", vars)
	w.mustConn3x("apply", "-auto-approve", "-no-color")
	if !hasFallback() {
		t.Fatal("fallback didn't run once the file was gone")
	}
	if starts() != 2 {
		t.Fatalf("fallback ran, but its handler didn't restart the service (%d starts)", starts())
	}
	if count("/var/log/app.init") != 1 {
		t.Fatal("init ran although the file is gone")
	}
	clean("after the answer flipped")
}

// Ask once whether a tool is there, install it when it isn't: the first
// apply installs, and the next plan, whose probe now says it's there, is
// clean, because a step that ran and is in line stays as it is while
// only_if is false.
func TestOnlyIfInstallWhenMissing(t *testing.T) {
	h := startHost(t, "debian13")
	w := newWorkdir(t, "only_if_install")
	w.writeAs("main.circuit.hcl", onlyIfVars{Port: h.port, KeyFile: h.keyFile, KnownHosts: h.knownHosts})
	w.mustConn3x("init", "-no-color")
	out := w.mustConn3x("plan", "-no-color")
	if strings.Contains(out, "will be read during apply") {
		t.Fatalf("a probe with no steps before it waited for the apply:\n%s", out)
	}
	w.mustConn3x("apply", "-auto-approve", "-no-color")
	installs := func() string { return strings.TrimSpace(h.exec("", "sh", "-c", "wc -l < /var/log/hello.installs")) }
	if got := strings.TrimSpace(h.exec("", "/usr/local/bin/hello")); got != "hello" || installs() != "1" {
		t.Fatalf("hello = %q, installs %s", got, installs())
	}
	if out := w.mustConn3x("plan", "-no-color"); !strings.Contains(out, "No changes.") {
		t.Fatalf("plan after the install isn't clean:\n%s", out)
	}

	// Someone removes the tool and the marker. The marker comes back; the
	// command, which already ran, doesn't run again on only_if alone.
	h.exec("", "rm", "/usr/local/bin/hello", "/etc/hello.installed")
	out = w.mustConn3x("apply", "-auto-approve", "-no-color")
	if !strings.Contains(out, "1 added, 0 changed, 0 destroyed") {
		t.Fatalf("apply after the tool was removed:\n%s", out)
	}
	h.exec("", "test", "-f", "/etc/hello.installed")
	if installs() != "1" {
		t.Fatalf("the command ran again (installs %s)", installs())
	}
}
