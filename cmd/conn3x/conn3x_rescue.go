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

// rescueHostsEnv gives a rescue phase's plan the hosts each rescue runs on
// (see configs.Conn3xRescueHosts).
const rescueHostsEnv = "CONN3X_RESCUE_HOSTS"

// A circuit's rescues run after an apply in which a step or handler they
// watch failed: apply reads which hosts it failed on from the apply's JSON
// stream, plans the rescues alone on those hosts, applies them, and drops
// them from state, so the next plan doesn't show them going. A rescued
// failure is still a failure, and apply still exits 1.

// listRescues says, under the plan, when each rescue runs.
func (r *batchRun) listRescues() {
	for _, rs := range r.rescues {
		fmt.Fprintf(r.out, "\nIf %s fails on a host, rescue %q of circuit %q runs there.", orList(rs.Watches), rs.Name, rs.Circuit)
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

// rescueHosts reads an apply's JSON stream for the hosts where a watched
// step or handler failed, by rescue resource name, and every such host.
func (r *batchRun) rescueHosts(stream string) (map[string][]string, []string, error) {
	in, err := os.Open(stream)
	if err != nil {
		return nil, nil, err
	}
	defer in.Close()
	rep := runreport.New("apply", time.Now())
	if err := rep.FromApply(in, false); err != nil {
		if _, long := err.(runreport.LongLines); !long {
			return nil, nil, err
		}
	}
	byRescue := map[string][]string{}
	var all []string
	for host, h := range rep.Hosts {
		for _, s := range h.Steps {
			if s.Status != runreport.StatusFailed || strings.HasPrefix(s.Address, "module.") {
				continue
			}
			circuit, step, _ := strings.Cut(s.Step, ".")
			for _, rs := range r.rescues {
				if rs.Circuit != circuit || !slices.Contains(rs.Watches, step) || slices.Contains(byRescue[rs.Resource()], host) {
					continue
				}
				byRescue[rs.Resource()] = append(byRescue[rs.Resource()], host)
				if !slices.Contains(all, host) {
					all = append(all, host)
				}
			}
		}
	}
	for _, hs := range byRescue {
		slices.SortFunc(hs, naturalCompare)
	}
	slices.SortFunc(all, naturalCompare)
	return byRescue, all, nil
}

// rescue runs the rescues for the watched steps that failed in the apply
// that wrote stream. It reports what went wrong itself; the apply has
// failed either way.
func (r *batchRun) rescue(stream string) {
	byRescue, hosts, err := r.rescueHosts(stream)
	if err != nil {
		r.errorf("reading which steps failed, for the rescues: %s", err)
		return
	}
	if len(hosts) == 0 {
		return
	}
	fmt.Fprintf(r.out, "\nRescuing %s:\n", strings.Join(hosts, ", "))
	js, _ := json.Marshal(byRescue)
	env := rescueHostsEnv + "=" + string(js)
	var planOut bytes.Buffer
	plan, code := r.plan(hosts, env, &planOut)
	switch code {
	case 0:
		fmt.Fprintln(r.out, "No rescue has anything to run on these hosts.")
		return
	case 1:
		_, _ = io.Copy(r.errOut, &planOut)
		r.errorf("the rescue plan failed, so no rescue ran.")
		return
	}
	var addrs, others []string
	for _, c := range plan.changes {
		_, isRescue := byRescue[c.name]
		switch {
		case !c.changes():
		case c.module != "" || !isRescue || c.actions != "create":
			others = append(others, c.addr)
		case !slices.Contains(addrs, c.typ+"."+c.name):
			addrs = append(addrs, c.typ+"."+c.name)
		}
	}
	if len(others) > 0 {
		r.errorf("the rescue plan changes more than the rescues:\n  %s\nSo no rescue ran.", strings.Join(others, "\n  "))
		return
	}
	code, _ = r.applySaved(plan.path, env)
	if err := r.forget(addrs); err != nil {
		r.errorf("dropping the rescues from state: %s\nRun conn3x state rm %s, or the next plan shows them being removed.", err, strings.Join(addrs, " "))
	}
	if code != 0 {
		r.errorf("a rescue failed, so %s may still be as the failed step left %s.", strings.Join(hosts, ", "), plural(len(hosts), "it", "them"))
		return
	}
	for _, h := range hosts {
		r.rescued[h] = true
	}
	fmt.Fprintf(r.out, "\nRescued %s. The apply still fails, because a step failed.\n", strings.Join(hosts, ", "))
}

// forget drops resources from state, as conn3x state rm does.
func (r *batchRun) forget(addrs []string) error {
	if len(addrs) == 0 {
		return nil
	}
	global, _ := r.split()
	var out bytes.Buffer
	if r.run(append(append(slices.Clone(global), "state", "rm"), addrs...), &out) != 0 {
		return fmt.Errorf("%s", strings.TrimSpace(out.String()))
	}
	return nil
}
