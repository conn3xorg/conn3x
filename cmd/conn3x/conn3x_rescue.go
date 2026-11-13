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

// rescueHostsEnv gives a rescue or always phase's plan the hosts each block
// runs on (see configs.Conn3xRescueHosts).
const rescueHostsEnv = "CONN3X_RESCUE_HOSTS"

// A circuit's rescues run after an apply in which a step or handler they
// watch failed: apply reads which hosts it failed on from the apply's JSON
// stream, plans the rescues alone on those hosts, applies them, and drops
// them from state, so the next plan doesn't show them going. Then its
// always blocks run the same way, on the hosts where a step or handler they
// watch ran, failed or not. A rescued failure is still a failure, and apply
// still exits 1.

// listRescues says, under the plan, when each rescue and always block runs.
func (r *batchRun) listRescues() {
	for _, rs := range r.rescues {
		if rs.Always {
			fmt.Fprintf(r.out, "\nAfter %s runs on a host, always %q of circuit %q runs there.", orList(rs.Watches), rs.Name, rs.Circuit)
		} else {
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

// rescueHosts reads an apply's JSON stream for the hosts where a watched
// step or handler failed, or for always blocks where one ran, by resource
// name, and every such host.
func (r *batchRun) rescueHosts(stream string, always bool) (map[string][]string, []string, error) {
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
	byBlock := map[string][]string{}
	var all []string
	for host, h := range rep.Hosts {
		for _, s := range h.Steps {
			ran := s.Status == runreport.StatusFailed || (always && s.Status == runreport.StatusOK)
			if !ran || strings.HasPrefix(s.Address, "module.") {
				continue
			}
			circuit, step, _ := strings.Cut(s.Step, ".")
			for _, rs := range r.rescues {
				if rs.Always != always || rs.Circuit != circuit || !slices.Contains(rs.Watches, step) || slices.Contains(byBlock[rs.Resource()], host) {
					continue
				}
				byBlock[rs.Resource()] = append(byBlock[rs.Resource()], host)
				if !slices.Contains(all, host) {
					all = append(all, host)
				}
			}
		}
	}
	for _, hs := range byBlock {
		slices.SortFunc(hs, naturalCompare)
	}
	slices.SortFunc(all, naturalCompare)
	return byBlock, all, nil
}

// afterApply runs the rescues, if the apply that wrote stream failed, and
// then the always blocks. It reports what went wrong itself, and returns
// false if an always block failed.
func (r *batchRun) afterApply(stream string, failed bool) bool {
	if failed {
		r.phase(stream, false)
	}
	return r.phase(stream, true)
}

// phase runs the rescues, or the always blocks, for the watched steps in
// the apply that wrote stream. It returns false if one of them failed, or
// couldn't run.
func (r *batchRun) phase(stream string, always bool) bool {
	byBlock, hosts, err := r.rescueHosts(stream, always)
	if err != nil {
		r.errorf("reading which steps ran, for the rescue and always blocks: %s", err)
		return false
	}
	if len(hosts) == 0 {
		return true
	}
	what := "rescue"
	if always {
		what = "always block"
		fmt.Fprintf(r.out, "\nRunning always blocks on %s:\n", strings.Join(hosts, ", "))
	} else {
		fmt.Fprintf(r.out, "\nRescuing %s:\n", strings.Join(hosts, ", "))
	}
	js, _ := json.Marshal(byBlock)
	env := rescueHostsEnv + "=" + string(js)
	var planOut bytes.Buffer
	plan, code := r.plan(hosts, env, &planOut)
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
		_, ours := byBlock[c.name]
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
	case code != 0 && always:
		r.errorf("an always block failed.")
		return false
	case code != 0:
		r.errorf("a rescue failed, so %s may still be as the failed step left %s.", strings.Join(hosts, ", "), plural(len(hosts), "it", "them"))
		return false
	case !always:
		for _, h := range hosts {
			r.rescued[h] = true
		}
		fmt.Fprintf(r.out, "\nRescued %s. The apply still fails, because a step failed.\n", strings.Join(hosts, ", "))
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
