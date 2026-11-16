// Copyright (c) The Conn3x Authors
// SPDX-License-Identifier: MPL-2.0

package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/opentofu/opentofu/internal/configs"
)

// brFakeConn3x stands in for the conn3x binary a batched apply runs. It
// logs each run, and answers from files in $BR_DIR, by the plan's key:
// its -limit, "all" without one, "target" with -target, prefixed "rescue."
// when a rescue phase plans. plan.KEY.N, or plan.KEY, is a plan's exit
// code on its first line, then its JSON for 2, or else what it prints;
// with neither the plan changes nothing. apply.KEY is the exit code of
// applying that plan, stream.KEY its -json-into stream, state the state
// list, and state.list or state.rm the exit code of that command.
const brFakeConn3x = `#!/bin/sh
d="$BR_DIR"
echo "$*" >> "$d/log"
eval "last=\${$#}"
case "$1" in
show) cat "$last"; exit 0 ;;
state) [ "$2" = list ] && cat "$d/state" 2>/dev/null; exit "$(cat "$d/state.$2" 2>/dev/null || echo 0)" ;;
esac
out= key=all stream=
for a; do
  case "$a" in
  -out=*) out=${a#-out=} ;;
  -limit=*) key=${a#-limit=} ;;
  -target=*) key=target ;;
  -json-into=*) stream=${a#-json-into=} ;;
  esac
done
[ -n "$CONN3X_RESCUE_HOSTS" ] && key="rescue.$key"
if [ "$1" = plan ]; then
  n=$(( $(cat "$d/n.$key" 2>/dev/null || echo 0) + 1 )); echo $n > "$d/n.$key"
  f="$d/plan.$key.$n"; [ -f "$f" ] || f="$d/plan.$key"
  [ -f "$f" ] || exit 0
  code=$(head -n 1 "$f")
  [ "$code" = 2 ] || { tail -n +2 "$f"; exit "$code"; }
  echo "$key" > "$out.key"
  tail -n +2 "$f" > "$out"
  exit 2
fi
key=$(cat "$last.key")
if [ -n "$stream" ]; then cat "$d/stream.$key" > "$stream" 2>/dev/null || : > "$stream"; fi
exit "$(cat "$d/apply.$key" 2>/dev/null || echo 0)"
`

type brBatchHost struct {
	t        *testing.T
	dir      string
	out, err bytes.Buffer
	r        *batchRun
}

// brBatchRun is a batched apply with args, through brFakeConn3x.
func brBatchRun(t *testing.T, args ...string) *brBatchHost {
	t.Helper()
	if runtime.GOOS == "windows" {
		t.Skip("the fake conn3x is a shell script")
	}
	h := &brBatchHost{t: t, dir: t.TempDir()}
	self := filepath.Join(h.dir, "conn3x")
	if err := os.WriteFile(self, []byte(brFakeConn3x), 0o755); err != nil {
		t.Fatal(err)
	}
	t.Setenv("BR_DIR", h.dir)
	h.r = &batchRun{self: self, dir: h.dir, tmp: t.TempDir(), args: append([]string{"apply"}, args...), out: &h.out, errOut: &h.err, in: strings.NewReader(""), rescued: map[string]bool{}}
	return h
}

// plan has the plan for key exit code with changes, each "type.name[key]
// action", or "type.name action" for one with no key. n, if given, is
// which plan for key this is.
func (h *brBatchHost) plan(key string, code int, changes []string, n ...int) {
	h.t.Helper()
	var rcs []map[string]any
	for _, c := range changes {
		addr, action, _ := strings.Cut(c, " ")
		typ, rest, _ := strings.Cut(addr, ".")
		name, idx, keyed := strings.Cut(rest, "[")
		rc := map[string]any{"address": addr, "mode": "managed", "type": typ, "name": name, "change": map[string]any{"actions": strings.Split(action, ",")}}
		if keyed {
			rc["index"] = strings.Trim(idx, `"]`)
		}
		rcs = append(rcs, rc)
	}
	js, _ := json.Marshal(map[string]any{"resource_changes": rcs})
	file := "plan." + key
	if len(n) > 0 {
		file += fmt.Sprintf(".%d", n[0])
	}
	h.write(file, fmt.Sprintf("%d\n%s\n", code, js))
}

func (h *brBatchHost) write(name, content string) {
	h.t.Helper()
	if err := os.WriteFile(filepath.Join(h.dir, name), []byte(content), 0o644); err != nil {
		h.t.Fatal(err)
	}
}

func (h *brBatchHost) log() string {
	b, _ := os.ReadFile(filepath.Join(h.dir, "log"))
	return string(b)
}

func (h *brBatchHost) applies() int { return strings.Count(h.log(), "apply ") }

var brWeb = []configs.Conn3xBatch{{Circuit: "web", Size: 1}}

// The usual shape of a plan: two hosts' steps and one other change.
func (h *brBatchHost) webPlans() {
	h.plan("all", 2, []string{`conn3x_command.web__a["web1"] create`, `conn3x_command.web__a["web2"] create`, "conn3x_file.other create"})
	h.plan("target", 2, []string{"conn3x_file.other create"})
	h.plan("web1", 2, []string{`conn3x_command.web__a["web1"] create`})
	h.plan("web2", 2, []string{`conn3x_command.web__a["web2"] create`})
}

// The other changes apply first, then each batch in turn.
func TestBatchRollsOut(t *testing.T) {
	h := brBatchRun(t, "-auto-approve")
	h.webPlans()
	if code := h.r.apply(brWeb); code != 0 {
		t.Fatalf("exit %d\n%s\n%s", code, h.out.String(), h.err.String())
	}
	for _, want := range []string{
		"First, 1 other change applies in one go:\n  conn3x_file.other",
		`Circuit "web" changes 2 hosts, which roll out in 2 batches of up to 1. No more batches start once more than 0 hosts have failed.`,
		"The other changes:",
		"Batch 1 of 2: web1",
		"Batch 2 of 2: web2",
		"All 2 batches applied.",
	} {
		if !strings.Contains(h.out.String(), want) {
			t.Errorf("%q isn't in\n%s", want, h.out.String())
		}
	}
	if n := h.applies(); n != 3 {
		t.Errorf("%d applies\n%s", n, h.log())
	}
	if !strings.Contains(h.log(), "plan -detailed-exitcode") || !strings.Contains(h.log(), "-limit=web1") {
		t.Errorf("log\n%s", h.log())
	}
}

// A batch whose hosts still have changes after it failed counts them;
// past max_failures nothing more starts.
func TestBatchStopsPastMaxFailures(t *testing.T) {
	h := brBatchRun(t, "-auto-approve")
	h.webPlans()
	h.write("apply.web1", "1")
	if code := h.r.apply(brWeb); code != 1 {
		t.Fatalf("exit %d", code)
	}
	want := "1 host failed, more than max_failures = 0, so no more batches start.\n  Failed: web1\n  Not reached: web2"
	if !strings.Contains(h.err.String(), want) || strings.Contains(h.out.String(), "Batch 2 of 2") {
		t.Errorf("out\n%s\nerr\n%s", h.out.String(), h.err.String())
	}
}

// Within max_failures every batch runs, and the apply still fails, naming
// the hosts. A percentage is counted from the hosts that change.
func TestBatchWithinMaxFailures(t *testing.T) {
	h := brBatchRun(t, "-auto-approve")
	h.webPlans()
	h.write("apply.web1", "1")
	if code := h.r.apply([]configs.Conn3xBatch{{Circuit: "web", Size: 1, FailedPercent: 50}}); code != 1 {
		t.Fatalf("exit %d", code)
	}
	if want := "every batch ran, and 1 host failed, within max_failures = 50% (1 of 2 hosts).\n  Failed: web1"; !strings.Contains(h.err.String(), want) {
		t.Errorf("err\n%s", h.err.String())
	}
	if !strings.Contains(h.out.String(), "Batch 2 of 2: web2") {
		t.Errorf("out\n%s", h.out.String())
	}
}

// Two circuits roll out one after the other, each batch named by its
// circuit, and a failure in the first keeps the second from starting.
func TestBatchTwoCircuits(t *testing.T) {
	h := brBatchRun(t, "-auto-approve")
	h.plan("all", 2, []string{`conn3x_command.web__a["web1"] create`, `conn3x_command.db__a["db1"] create`})
	h.plan("web1", 2, []string{`conn3x_command.web__a["web1"] create`})
	h.plan("db1", 2, []string{`conn3x_command.db__a["db1"] create`})
	h.write("apply.web1", "1")
	bs := []configs.Conn3xBatch{{Circuit: "web", Size: 1, MaxFailures: 1}, {Circuit: "db", Size: 1}}
	if code := h.r.apply(bs); code != 1 {
		t.Fatalf("exit %d", code)
	}
	for _, want := range []string{"Each circuit rolls out after the one before it, in this order.", `Circuit "web", batch 1 of 1: web1`} {
		if !strings.Contains(h.out.String(), want) {
			t.Errorf("%q isn't in\n%s", want, h.out.String())
		}
	}
	if want := `Not started, since they may depend on the failed hosts: circuit "db"`; !strings.Contains(h.err.String(), want) || strings.Contains(h.out.String(), `Circuit "db", batch`) {
		t.Errorf("out\n%s\nerr\n%s", h.out.String(), h.err.String())
	}
}

// Every way a batch's plans go wrong stops the rollout with code 1 and
// says why.
func TestBatchRefusesWhatTheApprovedPlanDidnt(t *testing.T) {
	for want, setup := range map[string]func(h *brBatchHost){
		"web1 is broken": func(h *brBatchHost) {
			h.write("plan.web1", "1\nweb1 is broken\n")
		},
		"batch 1's plan has changes the approved plan didn't:\n  conn3x_command.web__b[\"web1\"]": func(h *brBatchHost) {
			h.plan("web1", 2, []string{`conn3x_command.web__a["web1"] create`, `conn3x_command.web__b["web1"] create`})
		},
		"batch 1's plan changes more than circuit \"web\":\n  conn3x_file.other": func(h *brBatchHost) {
			h.plan("web1", 2, []string{`conn3x_command.web__a["web1"] create`, "conn3x_file.other create"})
		},
		"the plan to see which hosts failed did too": func(h *brBatchHost) {
			h.write("apply.web1", "1")
			h.write("plan.web1.2", "1\n")
		},
		"need batched steps first:\n  conn3x_command.web__a[\"web1\"]": func(h *brBatchHost) {
			h.plan("target", 2, []string{"conn3x_file.other create", `conn3x_command.web__a["web1"] create`})
		},
		"the plan for the changes outside the batched circuits has changes the approved plan didn't": func(h *brBatchHost) {
			h.plan("target", 2, []string{"conn3x_file.other create", "conn3x_file.new create"})
		},
		"target plan failed": func(h *brBatchHost) {
			h.write("plan.target", "1\ntarget plan failed\n")
		},
		"the changes outside the batched circuits failed, so no batch starts.": func(h *brBatchHost) {
			h.write("apply.target", "1")
		},
	} {
		t.Run(strings.SplitN(want, ":", 2)[0], func(t *testing.T) {
			h := brBatchRun(t, "-auto-approve")
			h.webPlans()
			setup(h)
			if code := h.r.apply(brWeb); code != 1 || !strings.Contains(h.err.String(), want) {
				t.Errorf("exit %d\nout\n%s\nerr\n%s", code, h.out.String(), h.err.String())
			}
		})
	}
}

// What doesn't need a rollout applies in one go: other changes found
// nothing to do after all, or no batched circuit changes at all.
func TestBatchWithoutRollout(t *testing.T) {
	h := brBatchRun(t, "-auto-approve")
	h.webPlans()
	h.write("plan.target", "0\n")
	if code := h.r.apply(brWeb); code != 0 || strings.Contains(h.out.String(), "First,") || h.applies() != 2 {
		t.Errorf("nothing outside after all: exit %d, %d applies\n%s", code, h.applies(), h.out.String())
	}

	h = brBatchRun(t, "-auto-approve")
	h.plan("all", 2, []string{"conn3x_file.other create"})
	if code := h.r.apply(brWeb); code != 0 || h.applies() != 1 {
		t.Errorf("no batched changes: exit %d, %d applies", code, h.applies())
	}
	h = brBatchRun(t, "-input=false")
	h.plan("all", 2, []string{"conn3x_file.other create"})
	if code := h.r.apply(brWeb); code != 1 || !strings.Contains(h.err.String(), "Apply cancelled.") || h.applies() != 0 {
		t.Errorf("not approved: exit %d, %q", code, h.err.String())
	}
	h = brBatchRun(t, "-input=false")
	h.webPlans()
	if code := h.r.apply(brWeb); code != 1 || !strings.Contains(h.err.String(), "-input=false needs -auto-approve to apply in batches") {
		t.Errorf("batches not approved: exit %d, %q", code, h.err.String())
	}
	for code, plan := range map[int]string{0: "0\n", 1: "1\nbroken\n"} {
		h = brBatchRun(t, "-auto-approve")
		h.write("plan.all", plan)
		if got := h.r.apply(brWeb); got != code || h.applies() != 0 {
			t.Errorf("whole plan exit %d: apply exit %d", code, got)
		}
	}
	// Circuits whose steps need each other can't roll out in any order.
	h = brBatchRun(t, "-auto-approve")
	h.write("plan.all", `2
{"resource_changes": [{"address": "conn3x_command.web__a[\"web1\"]", "mode": "managed", "type": "conn3x_command", "name": "web__a", "index": "web1", "change": {"actions": ["create"]}}],
 "configuration": {"root_module": {"resources": [
  {"address": "conn3x_command.web__a", "depends_on": ["conn3x_command.db__a"]},
  {"address": "conn3x_command.db__a", "expressions": {"command": {"references": ["conn3x_command.web__a.stdout", "conn3x_command.web__a"]}}}]}}}
`)
	if code := h.r.apply([]configs.Conn3xBatch{{Circuit: "web", Size: 1}, {Circuit: "db", Size: 1}}); code != 1 || !strings.Contains(h.err.String(), "depend on each other") {
		t.Errorf("a cycle: exit %d, %q", code, h.err.String())
	}
}

// A prereq runs on the hosts about to change, in a plan of its own, and
// is dropped from state; then the batch plans again and applies.
func TestBatchRunsPrereqs(t *testing.T) {
	h := brBatchRun(t, "-auto-approve")
	h.r.rescues = []configs.Conn3xRescue{{Circuit: "web", Name: "drain", Kind: "prereq", Watches: []string{"a"}}}
	h.plan("all", 2, []string{`conn3x_command.web__a["web1"] create`})
	h.plan("rescue.web1", 2, []string{`conn3x_command.web__drain["web1"] create`})
	h.write("state", "conn3x_command.web__drain[\"web1\"]\nconn3x_command.web__a[\"web1\"]\n")
	if code := h.r.apply(nil); code != 0 {
		t.Fatalf("exit %d\n%s\n%s", code, h.out.String(), h.err.String())
	}
	for _, want := range []string{`Before a changes on a host, prereq "drain" of circuit "web" runs there.`, "Running prereqs on web1:"} {
		if !strings.Contains(h.out.String(), want) {
			t.Errorf("%q isn't in\n%s", want, h.out.String())
		}
	}
	if !strings.Contains(h.log(), `state rm conn3x_command.web__drain`) || h.applies() != 2 {
		t.Errorf("log\n%s", h.log())
	}
}

// A prereq that fails, or plans more than prereqs, stops the apply before
// anything it's before.
func TestBatchPrereqFailures(t *testing.T) {
	for want, setup := range map[string]func(h *brBatchHost){
		"a prereq failed.":                          func(h *brBatchHost) { h.write("apply.rescue.web1", "1") },
		"the prereq plan failed, so no prereq ran.": func(h *brBatchHost) { h.write("plan.rescue.web1", "1\n") },
		"the prereq plan changes more than the prereqs:": func(h *brBatchHost) {
			h.plan("rescue.web1", 2, []string{`conn3x_command.web__drain["web1"] create`, `conn3x_command.web__a["web1"] update`})
		},
		"planning again after the prereqs failed": func(h *brBatchHost) { h.write("plan.all.2", "1\n") },
		"after the prereqs, the plan has changes the appro": func(h *brBatchHost) {
			h.plan("all", 2, []string{`conn3x_command.web__a["web1"] create`, "conn3x_file.x create"}, 2)
		},
		"dropping the prereqs from state": func(h *brBatchHost) { h.write("state.list", "1") },
	} {
		t.Run(want, func(t *testing.T) {
			h := brBatchRun(t, "-auto-approve")
			h.r.rescues = []configs.Conn3xRescue{{Circuit: "web", Name: "drain", Kind: "prereq", Watches: []string{"a"}}}
			h.plan("all", 2, []string{`conn3x_command.web__a["web1"] create`})
			h.plan("rescue.web1", 2, []string{`conn3x_command.web__drain["web1"] create`})
			setup(h)
			code := h.r.apply(nil)
			if !strings.Contains(h.err.String(), want) {
				t.Errorf("exit %d, err\n%s", code, h.err.String())
			}
		})
	}
	// Nothing left after the prereqs is a success with no apply.
	h := brBatchRun(t, "-auto-approve")
	h.r.rescues = []configs.Conn3xRescue{{Circuit: "web", Name: "drain", Kind: "prereq", Watches: []string{"a"}}}
	h.plan("all", 2, []string{`conn3x_command.web__a["web1"] create`})
	h.write("plan.all.2", "0\n")
	if code := h.r.apply(nil); code != 0 || !strings.Contains(h.out.String(), "No prereq has anything to run on these hosts.") || h.applies() != 0 {
		t.Errorf("exit %d, %d applies\n%s", code, h.applies(), h.out.String())
	}
}

// A failed apply runs the rescues on the hosts that failed, then the
// always blocks where a watched step ran; the apply still fails.
func TestBatchRescuesAndAlways(t *testing.T) {
	stream := `{"type":"apply_errored","hook":{"resource":{"addr":"conn3x_command.web__a[\"web1\"]"}}}
{"type":"apply_complete","hook":{"resource":{"addr":"conn3x_command.web__a[\"web2\"]"}}}
`
	setup := func(t *testing.T) *brBatchHost {
		h := brBatchRun(t, "-auto-approve")
		h.r.rescues = []configs.Conn3xRescue{
			{Circuit: "web", Name: "restore", Kind: "rescue", Watches: []string{"a"}},
			{Circuit: "web", Name: "lb", Kind: "always", Watches: []string{"a"}},
		}
		h.plan("all", 2, []string{`conn3x_command.web__a["web1"] create`, `conn3x_command.web__a["web2"] create`})
		h.write("stream.all", stream)
		h.write("apply.all", "1")
		h.plan("rescue.web1", 2, []string{`conn3x_command.web__restore["web1"] create`})
		h.plan("rescue.web1,web2", 2, []string{`conn3x_command.web__lb["web1"] create`, `conn3x_command.web__lb["web2"] create`})
		return h
	}
	h := setup(t)
	if code := h.r.apply(nil); code != 1 {
		t.Fatalf("exit %d", code)
	}
	for _, want := range []string{
		`If a fails on a host, rescue "restore" of circuit "web" runs there.`,
		`After a runs on a host, always "lb" of circuit "web" runs there.`,
		"Rescuing web1:", "Rescued web1. The apply still fails", "Running always blocks on web1, web2:",
	} {
		if !strings.Contains(h.out.String(), want) {
			t.Errorf("%q isn't in\n%s", want, h.out.String())
		}
	}
	if !h.r.rescued["web1"] || h.r.rescued["web2"] {
		t.Errorf("rescued %v", h.r.rescued)
	}

	for want, more := range map[string]func(h *brBatchHost){
		"a rescue failed, so web1 may still be as the failed step left it.": func(h *brBatchHost) { h.write("apply.rescue.web1", "1") },
		"an always block failed.": func(h *brBatchHost) { h.write("apply.rescue.web1,web2", "1") },
	} {
		h := setup(t)
		more(h)
		if code := h.r.apply(nil); code != 1 || !strings.Contains(h.err.String(), want) {
			t.Errorf("%s: exit %d, err\n%s", want, code, h.err.String())
		}
	}
	// A clean apply runs only the always blocks, and an always block that
	// fails fails the apply.
	h = setup(t)
	h.write("apply.all", "0")
	h.write("apply.rescue.web1,web2", "1")
	if code := h.r.apply(nil); code != 1 || strings.Contains(h.out.String(), "Rescuing") || !strings.Contains(h.err.String(), "an always block failed.") {
		t.Errorf("exit %d\nout\n%s\nerr\n%s", code, h.out.String(), h.err.String())
	}
}

// -report writes one report from every apply's stream, with the
// rollout's own errors in it.
func TestBatchWritesOneReport(t *testing.T) {
	h := brBatchRun(t, "-auto-approve")
	h.webPlans()
	h.write("apply.web1", "1")
	h.r.reportPath = filepath.Join(t.TempDir(), "report.json")
	h.write("stream.web2", `{"type":"apply_complete","hook":{"resource":{"addr":"conn3x_command.web__a[\"web2\"]"}}}`+"\n")
	if code := h.r.apply([]configs.Conn3xBatch{{Circuit: "web", Size: 1, MaxFailures: 1}}); code != 1 {
		t.Fatalf("exit %d", code)
	}
	h.r.rescued["web2"] = true
	if err := h.r.writeReport(time.Now(), false); err != nil {
		t.Fatal(err)
	}
	b, err := os.ReadFile(h.r.reportPath)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(b), "within max_failures") || !strings.Contains(string(b), `"web2"`) {
		t.Errorf("report %s", b)
	}
	h.r.streams = append(h.r.streams, batchStream{path: filepath.Join(t.TempDir(), "gone.jsonl")})
	if err := h.r.writeReport(time.Now(), false); err == nil {
		t.Error("wrote a report from a stream that isn't there")
	}
}
