// Copyright (c) The Conn3x Authors
// SPDX-License-Identifier: MPL-2.0

package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"slices"
	"strings"
	"time"

	runreport "github.com/opentofu/opentofu/internal/conn3x/report"
)

// rescueHostsEnv gives a prereq, rescue or always phase's plan the hosts
// each block runs on (see configs.Conn3xRescueHosts).
const rescueHostsEnv = "CONN3X_RESCUE_HOSTS"

// A circuit's prereqs run before an apply, on the hosts where a step they're
// before is about to change: apply plans the prereqs alone on those hosts,
// applies them, drops them from state, and plans again. Its rescues run
// after an apply in which a step or handler they watch failed: apply reads
// which hosts it failed on from the apply's JSON stream and runs the
// rescues there the same way. Then its always blocks run, on the hosts
// where a step or handler they watch ran, failed or not. A rescued failure
// is still a failure, and apply still exits 1.

// listRescues says, under the plan, when each prereq, rescue and always
// block runs.
func (r *batchRun) listRescues() {
	for _, rs := range r.rescues {
		switch rs.Kind {
		case "prereq":
			fmt.Fprintf(r.out, "\nBefore %s changes on a host, prereq %q of circuit %q runs there.", orList(rs.Watches), rs.Name, rs.Circuit)
		case "always":
			fmt.Fprintf(r.out, "\nAfter %s runs on a host, always %q of circuit %q runs there.", orList(rs.Watches), rs.Name, rs.Circuit)
		default:
			fmt.Fprintf(r.out, "\nIf %s fails on a host, rescue %q of circuit %q runs there.", orList(rs.Watches), rs.Name, rs.Circuit)
		}
	}
	if len(r.rescues) > 0 {
		fmt.Fprintln(r.out)
	}
}

// orList is "a", "a or b", "a, b or c".
func orList(names []string) string {
	if len(names) < 2 {
		return strings.Join(names, "")
	}
	return strings.Join(names[:len(names)-1], ", ") + " or " + names[len(names)-1]
}

// phaseHosts collects, for the blocks of kind, the hosts each runs on.
type phaseHosts struct {
	byBlock map[string][]string // resource name to hosts
	all     []string
}

// add records that circuit's step ran, or will, on host, for every block
// of kind that goes with it.
func (r *batchRun) add(ph *phaseHosts, kind, circuit, step, host string) {
	for _, rs := range r.rescues {
		if rs.Kind != kind || rs.Circuit != circuit || !slices.Contains(rs.Watches, step) || slices.Contains(ph.byBlock[rs.Resource()], host) {
			continue
		}
		ph.byBlock[rs.Resource()] = append(ph.byBlock[rs.Resource()], host)
		if !slices.Contains(ph.all, host) {
			ph.all = append(ph.all, host)
		}
	}
}

func (ph *phaseHosts) sort() {
	for _, hs := range ph.byBlock {
		slices.SortFunc(hs, naturalCompare)
	}
	slices.SortFunc(ph.all, naturalCompare)
}

// rescueHosts reads an apply's JSON stream for the hosts where a watched
// step or handler failed, or for always blocks where one ran.
func (r *batchRun) rescueHosts(stream, kind string) (*phaseHosts, error) {
	in, err := os.Open(stream)
	if err != nil {
		return nil, err
	}
	defer in.Close()
	rep := runreport.New("apply", time.Now())
	if err := rep.FromApply(in, false); err != nil {
		if _, long := err.(runreport.LongLines); !long {
			return nil, err
		}
	}
	ph := &phaseHosts{byBlock: map[string][]string{}}
	for host, h := range rep.Hosts {
		for _, s := range h.Steps {
			ran := s.Status == runreport.StatusFailed || (kind == "always" && s.Status == runreport.StatusOK)
			if !ran || strings.HasPrefix(s.Address, "module.") {
				continue
			}
			circuit, step, _ := strings.Cut(s.Step, ".")
			r.add(ph, kind, circuit, step, host)
		}
	}
	ph.sort()
	return ph, nil
}

// prereqHosts reads a plan for the hosts where a step a prereq is before
// is about to change.
func (r *batchRun) prereqHosts(p *batchPlan) *phaseHosts {
	ph := &phaseHosts{byBlock: map[string][]string{}}
	for _, c := range p.changes {
		key, ok := c.key.(string)
		circuit, step, isStep := strings.Cut(c.name, "__")
		if !c.changes() || !ok || !isStep || c.module != "" {
			continue
		}
		// shortcut: a looping step's key is host/item, and the host is taken
		// to end at the first "/", as the report does; a host name holding
		// "/" gets no prereq. Read the host from the plan if that comes up.
		host, _, _ := strings.Cut(key, "/")
		r.add(ph, "prereq", circuit, step, host)
	}
	ph.sort()
	return ph
}

// prereqs runs the prereqs for the steps p is about to change, on the hosts
// where it changes them, then plans p again, since their apply changed the
// state p was planned from. It returns the plan to apply, nil if nothing is
// left to change, and false if a prereq failed or the new plan differs.
func (r *batchRun) prereqs(p *batchPlan) (*batchPlan, bool) {
	ph := r.prereqHosts(p)
	if len(ph.all) == 0 {
		return p, true
	}
	if !r.phase("prereq", ph) {
		r.errorf("a prereq didn't run, so nothing it's before was applied.")
		return nil, false
	}
	var planOut bytes.Buffer
	again, code := r.plan(p.hosts, p.env, &planOut, p.extra...)
	switch code {
	case 0:
		return nil, true
	case 1:
		_, _ = io.Copy(r.errOut, &planOut)
		r.errorf("planning again after the prereqs failed, so nothing they're before was applied.")
		return nil, false
	}
	if extra := again.notIn(p); len(extra) > 0 {
		r.errorf("after the prereqs, the plan has changes the approved plan didn't:\n  %s\nSo nothing else was applied; run the apply again to see them.", strings.Join(extra, "\n  "))
		return nil, false
	}
	return again, true
}

// afterApply runs the rescues, if the apply that wrote stream failed, and
// then the always blocks. It reports what went wrong itself, and returns
// false if an always block failed.
func (r *batchRun) afterApply(stream string, failed bool) bool {
	kinds := []string{"always"}
	if failed {
		kinds = []string{"rescue", "always"}
	}
	ok := true
	for _, kind := range kinds {
		ph, err := r.rescueHosts(stream, kind)
		if err != nil {
			r.errorf("reading which steps ran, for the rescue and always blocks: %s", err)
			return false
		}
		if !r.phase(kind, ph) && kind == "always" {
			ok = false
		}
	}
	return ok
}

// phase runs the blocks of kind on the hosts ph gives each, in a plan of
// their own, and drops them from state. It returns false if one of them
// failed, or couldn't run.
func (r *batchRun) phase(kind string, ph *phaseHosts) bool {
	if len(ph.all) == 0 {
		return true
	}
	hosts := strings.Join(ph.all, ", ")
	what := kind
	switch kind {
	case "always":
		what = "always block"
		fmt.Fprintf(r.out, "\nRunning always blocks on %s:\n", hosts)
	case "prereq":
		fmt.Fprintf(r.out, "\nRunning prereqs on %s:\n", hosts)
	default:
		fmt.Fprintf(r.out, "\nRescuing %s:\n", hosts)
	}
	js, _ := json.Marshal(ph.byBlock)
	env := rescueHostsEnv + "=" + string(js)
	var planOut bytes.Buffer
	plan, code := r.plan(ph.all, env, &planOut)
	switch code {
	case 0:
		fmt.Fprintf(r.out, "No %s has anything to run on these hosts.\n", what)
		return true
	case 1:
		_, _ = io.Copy(r.errOut, &planOut)
		r.errorf("the %s plan failed, so no %s ran.", what, what)
		return false
	}
	var addrs, others []string
	for _, c := range plan.changes {
		_, ours := ph.byBlock[c.name]
		switch {
		case !c.changes():
		case c.module != "" || !ours || c.actions != "create":
			others = append(others, c.addr)
		case !slices.Contains(addrs, c.typ+"."+c.name):
			addrs = append(addrs, c.typ+"."+c.name)
		}
	}
	if len(others) > 0 {
		r.errorf("the %s plan changes more than the %ss:\n  %s\nSo no %s ran.", what, what, strings.Join(others, "\n  "), what)
		return false
	}
	code, _ = r.applySaved(plan.path, env)
	if err := r.forget(addrs); err != nil {
		r.errorf("dropping the %ss from state: %s\nRun conn3x state rm %s, or the next plan shows them being removed.", what, err, strings.Join(addrs, " "))
	}
	switch {
	case code != 0 && kind == "rescue":
		r.errorf("a rescue failed, so %s may still be as the failed step left %s.", hosts, plural(len(ph.all), "it", "them"))
		return false
	case code != 0 && kind == "always":
		r.errorf("an always block failed.")
		return false
	case code != 0:
		r.errorf("a %s failed.", what)
		return false
	case kind == "rescue":
		for _, h := range ph.all {
			r.rescued[h] = true
		}
		fmt.Fprintf(r.out, "\nRescued %s. The apply still fails, because a step failed.\n", hosts)
	}
	return true
}

// forget drops resources from state, as conn3x state rm does. Those that
// failed on every host never reached state, and are passed over.
func (r *batchRun) forget(addrs []string) error {
	if len(addrs) == 0 {
		return nil
	}
	global, _ := r.split()
	var list bytes.Buffer
	if r.run(append(slices.Clone(global), "state", "list"), &list) != 0 {
		return fmt.Errorf("%s", strings.TrimSpace(list.String()))
	}
	inState := slices.DeleteFunc(slices.Clone(addrs), func(a string) bool {
		return !slices.ContainsFunc(strings.Split(list.String(), "\n"), func(line string) bool {
			return line == a || strings.HasPrefix(line, a+"[")
		})
	})
	if len(inState) == 0 {
		return nil
	}
	var out bytes.Buffer
	if r.run(append(append(slices.Clone(global), "state", "rm"), inState...), &out) != 0 {
		return fmt.Errorf("%s", strings.TrimSpace(out.String()))
	}
	return nil
}
