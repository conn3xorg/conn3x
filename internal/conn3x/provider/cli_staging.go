// Copyright (c) The Conn3x Authors
// SPDX-License-Identifier: MPL-2.0

package provider

import (
	"context"
	"errors"
	"fmt"
	"log"
	"strings"
	"sync"
	"time"

	"github.com/zclconf/go-cty/cty"

	"github.com/opentofu/opentofu/internal/providers"
	"github.com/opentofu/opentofu/internal/tfdiags"
)

// cliStaged is what one device's steps in a circuit have staged in this
// run. Unlike EOS, Junos keeps nothing between logins, so the lines wait
// here, and the circuit's conn3x_junos_commit sends them all in one commit
// confirmed. Callers hold lockHost(h, "junos").
type cliStaged struct {
	p        *cliPlatform
	h        *hostConn
	base     string     // the configuration the first staged step read
	cmds     []string   // every staged line, in order; nil: nothing staged
	removals [][]string // staged removals: their steps are already forgotten
	conn     cty.Value  // the ssh block they came with, to commit them again
	// owner is the circuit whose steps staged the lines. A device holds one
	// circuit's at a time: another circuit's commit in between would leave
	// base stale, and the owner's commit would then refuse.
	owner   string
	touched time.Time
	failed  map[string]error // by circuit: its staged lines were dropped
	batch   map[string]bool  // circuits being destroyed: removals stage for conn3x_junos_removals
}

var cliStages = struct {
	sync.Mutex
	m map[string]*cliStaged // platform name and rootKey
}{m: map[string]*cliStaged{}}

func cliStagedOn(p *cliPlatform, h *hostConn) *cliStaged {
	cliStages.Lock()
	defer cliStages.Unlock()
	key := p.name + "\x00" + h.rootKey
	st, ok := cliStages.m[key]
	if !ok {
		st = &cliStaged{p: p, h: h}
		cliStages.m[key] = st
	}
	return st
}

// turn waits until no other circuit has lines staged on the device, as
// staged.turn does for EOS, and gives up on one idle for eosTurnIdle.
func (st *cliStaged) turn(ctx context.Context, h *hostConn, circuit string, unlock func()) (func(), error) {
	for st.cmds != nil && st.owner != circuit {
		if idle := time.Since(st.touched); idle > eosTurnIdle {
			return unlock, fmt.Errorf("not applied: circuit %q has lines staged for %s that it has neither committed nor added to for %s, so this circuit's turn on the device never came. %q may have stopped at an error, or its next step may be waiting on something slow that isn't on the device. Apply again once it has committed or its error is fixed", st.owner, h.host, eosTurnIdle, st.owner)
		}
		unlock()
		select {
		case <-ctx.Done():
			return func() {}, ctx.Err()
		case <-time.After(eosTurnPoll):
		}
		unlock = lockHost(h, st.p.name)
	}
	return unlock, nil
}

// stage adds a step's lines to its circuit's, after a dry run of all of
// them, so a refusal fails the step that brought it. A refusal drops
// everything staged for the circuit: nothing of it reaches the device.
func (st *cliStaged) stage(ctx context.Context, h *hostConn, circuit, view string, cmds []string, removal bool, conn cty.Value) error {
	all := append(append([]string{}, st.cmds...), cmds...)
	if err := st.p.check(ctx, h.client, all); err != nil {
		return st.drop(ctx, h, circuit, err)
	}
	if st.cmds == nil {
		st.base, st.owner = view, circuit
	}
	st.cmds = all
	if removal {
		st.removals, st.conn = append(st.removals, cmds), conn
	}
	return nil
}

// drop forgets what circuit staged, after err, and marks it failed on the
// device for the rest of the run. Removals in it are committed on their
// own, since their steps are already gone from state.
func (st *cliStaged) drop(ctx context.Context, h *hostConn, circuit string, err error) error {
	if st.cmds != nil && st.owner == circuit {
		err = fmt.Errorf("%w. The lines earlier steps of this circuit staged for %s were dropped too, so nothing of it reached the device", err, h.host)
		err, _ = st.salvage(ctx, h, st.removals, err)
		st.cmds, st.removals = nil, nil
	}
	if circuit == "" {
		return err // a step outside a circuit stages nothing for others to skip
	}
	if st.failed == nil {
		st.failed = map[string]error{}
	}
	st.failed[circuit] = err
	return err
}

// salvage commits removed, the removals of lines that went nowhere, on
// their own. It returns err, saying what became of them, and whether the
// device still has them.
func (st *cliStaged) salvage(ctx context.Context, h *hostConn, removed [][]string, err error) (_ error, left bool) {
	if len(removed) == 0 {
		return err, false
	}
	var cmds, lines []string
	for _, r := range removed {
		cmds = append(cmds, r...)
		lines = append(lines, strings.Join(r, "; "))
	}
	again := func() error {
		running, err := st.p.running(ctx, h.client)
		if err != nil {
			return err
		}
		_, err = st.p.apply(ctx, h.client, st.p.reconnect(st.conn), running, cmds, st.p.confirmAfter(st.conn))
		return err
	}
	if againErr := again(); againErr != nil {
		return fmt.Errorf("%w. Removals staged with them couldn't be committed on their own either (%v). Conn3x has already forgotten them, so remove these by hand: %s", err, againErr, strings.Join(lines, " | ")), true
	}
	return fmt.Errorf("%w. The removals staged with them were committed on their own, so the device no longer has them: %s", err, strings.Join(lines, " | ")), false
}

// commit sends what circuit staged in one commit confirmed. Nothing staged,
// or another circuit's lines, is nothing to do.
func (st *cliStaged) commit(ctx context.Context, h *hostConn, circuit string, conn cty.Value, what string) error {
	if err := st.failed[circuit]; err != nil {
		return fmt.Errorf("%s: nothing was committed: %w", what, err)
	}
	if st.cmds == nil || st.owner != circuit {
		return nil
	}
	base, cmds, removed := st.base, st.cmds, st.removals
	st.cmds, st.removals = nil, nil // committed or rolling back: either way, gone
	diff, err := st.p.apply(ctx, h.client, st.p.reconnect(conn), base, cmds, st.p.confirmAfter(conn))
	if diff != "" {
		log.Printf("[INFO] conn3x: %s on %s: lines sent:\n%s", what, h.host, diff)
	}
	if err == nil {
		return nil
	}
	if st.p.notLive(err) {
		err, _ = st.salvage(ctx, h, removed, err)
	}
	return fmt.Errorf("%s: %w. The steps are recorded as applied, so the next refresh finds them out of sync and the next apply makes them again", what, err)
}

// finishCLI ends a run for the Junos steps: lines staged for a commit
// that never came are dropped, and their removals committed on their own.
// It returns what that left on a device.
func finishCLI() error {
	cliStages.Lock()
	defer cliStages.Unlock()
	var left []error
	for key, st := range cliStages.m {
		if st.cmds != nil {
			log.Printf("[WARN] conn3x: dropping lines staged for %s, which no conn3x_junos_commit sent", st.h.host)
		}
		if st.cmds != nil && len(st.removals) > 0 {
			// Up to five minutes: a commit, its wait and the confirm.
			ctx, cancel := context.WithTimeout(context.Background(), st.p.revertAfter)
			if err, still := st.salvage(ctx, st.h, st.removals, errors.New("the run stopped before the commit")); still {
				left = append(left, fmt.Errorf("%s: %w", st.h.host, err))
			} else {
				log.Printf("[WARN] conn3x: %v", err)
			}
			cancel()
		}
		delete(cliStages.m, key)
	}
	return errors.Join(left...)
}

// cliCommitSchema is conn3x_<platform>_commit's: EOS's, in the platform's words.
func cliCommitSchema(p *cliPlatform) func() providers.Schema {
	return func() providers.Schema {
		s := eosCommitSchema()
		s.Block.Description = junosExperimental + "Commits the lines a circuit's " + p.name + "_* steps staged for one device, in one commit with a rollback timer, waits confirm_after, confirms over a new login. Circuits add it; it isn't a step."
		s.Block.Attributes["triggers"].Description = "The revisions of the circuit's " + p.name + " steps on this device; the commit runs when they change."
		s.Block.Attributes["removals"].Description = "The id of the circuit's conn3x_" + p.name + "_removals on this device. With one, destroying the circuit stages the steps' removals for it to commit once."
		return s
	}
}

func cliRemovalsSchema(p *cliPlatform) func() providers.Schema {
	return func() providers.Schema {
		s := eosRemovalsSchema()
		s.Block.Description = junosExperimental + "Commits, once, the removals a destroyed circuit's " + p.name + "_* steps staged for the device. Circuits add it; it isn't a step."
		return s
	}
}

func planIDOnly(kind string) func(providers.PlanResourceChangeRequest) providers.PlanResourceChangeResponse {
	return func(req providers.PlanResourceChangeRequest) providers.PlanResourceChangeResponse {
		var resp providers.PlanResourceChangeResponse
		if req.ProposedNewState.IsNull() {
			resp.PlannedState = req.ProposedNewState
			return resp
		}
		vals := req.ProposedNewState.AsValueMap()
		vals["id"] = planID(req, kind)
		resp.PlannedState = cty.ObjectVal(vals)
		return resp
	}
}

func applyCLICommit(p *cliPlatform) func(context.Context, providers.ApplyResourceChangeRequest) providers.ApplyResourceChangeResponse {
	return func(ctx context.Context, req providers.ApplyResourceChangeRequest) providers.ApplyResourceChangeResponse {
		resp := providers.ApplyResourceChangeResponse{NewState: req.PlannedState}
		destroying := req.PlannedState.IsNull()
		obj := req.PlannedState
		if destroying {
			obj = req.PriorState
		}
		conn := obj.GetAttr("ssh")
		h, err := pooled(ctx, conn, 0)
		if err != nil {
			resp.Diagnostics = resp.Diagnostics.Append(attrError("ssh", err.Error()))
			return resp
		}
		defer lockHost(h, p.name)()
		st := cliStagedOn(p, h)
		circuit := eosCircuit(obj)
		if destroying {
			// The steps' removals come next, then the removals resource commits them.
			if st.batch == nil {
				st.batch = map[string]bool{}
			}
			st.batch[circuit] = true
			return resp
		}
		if err := st.commit(ctx, h, circuit, conn, p.name+" commit"); err != nil {
			resp.Diagnostics = resp.Diagnostics.Append(err)
		}
		return resp
	}
}

func applyCLIRemovals(p *cliPlatform) func(context.Context, providers.ApplyResourceChangeRequest) providers.ApplyResourceChangeResponse {
	return func(ctx context.Context, req providers.ApplyResourceChangeRequest) providers.ApplyResourceChangeResponse {
		resp := providers.ApplyResourceChangeResponse{NewState: req.PlannedState}
		if !req.PlannedState.IsNull() {
			return resp
		}
		conn := req.PriorState.GetAttr("ssh")
		h, err := pooled(ctx, conn, 0)
		if err != nil {
			resp.Diagnostics = resp.Diagnostics.Append(attrError("ssh", err.Error()))
			return resp
		}
		defer lockHost(h, p.name)()
		st := cliStagedOn(p, h)
		circuit := eosCircuit(req.PriorState)
		delete(st.batch, circuit) // a removal after this, out of order, commits on its own
		if err := st.commit(ctx, h, circuit, conn, p.name+" removals"); err != nil {
			resp.Diagnostics = resp.Diagnostics.Append(err)
		}
		return resp
	}
}

// cliCommitTypes are the resources circuits add for a platform's devices.
func cliCommitTypes(p *cliPlatform) map[string]resourceType {
	commit, removals := cliCommitSchema(p), cliRemovalsSchema(p)
	none := func(cty.Value) tfdiags.Diagnostics { return nil }
	return map[string]resourceType{
		"conn3x_" + p.name + "_commit":   {commit, none, planIDOnly(p.name + "-commit"), readEOSCommit, applyCLICommit(p), upgradeWith(commit)},
		"conn3x_" + p.name + "_removals": {removals, none, planIDOnly(p.name + "-removals"), readEOSCommit, applyCLIRemovals(p), upgradeWith(removals)},
	}
}

// junosCommitTypes are Junos's.
var junosCommitTypes = cliCommitTypes(junosPlatform)
