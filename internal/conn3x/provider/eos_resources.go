// Copyright (c) The Conn3x Authors
// SPDX-License-Identifier: MPL-2.0

package provider

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"errors"
	"fmt"
	"log"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/zclconf/go-cty/cty"

	"github.com/opentofu/opentofu/internal/configs/configschema"
	"github.com/opentofu/opentofu/internal/conn3x/modules/eos"
	"github.com/opentofu/opentofu/internal/conn3x/transport/ssh"
	"github.com/opentofu/opentofu/internal/providers"
	"github.com/opentofu/opentofu/internal/tfdiags"
)

const eosTypePrefix = "conn3x_eos_"

// eosExperimental starts every EOS description, so the reference says so.
const eosExperimental = "Experimental. "

// validateEOSSSH rejects the ssh settings a switch's CLI has no use for:
// there is no shell for the agent and no sudo for become.
func validateEOSSSH(cfg cty.Value) tfdiags.Diagnostics {
	var diags tfdiags.Diagnostics
	if cfg.IsNull() || !cfg.Type().HasAttribute("ssh") {
		return diags
	}
	conn := cfg.GetAttr("ssh")
	if conn.IsNull() || !conn.IsKnown() {
		return diags
	}
	for attr, why := range map[string]string{
		"agent":                "The conn3x agent needs a shell, and an EOS login has the switch's CLI instead. Remove agent from this ssh block.",
		"become":               "EOS has no sudo. Log in as a user with privilege 15 (\"username x privilege 15 role network-admin\") on a switch with \"aaa authorization exec default local\", so the login starts privileged, and remove become from this ssh block.",
		"become_password_file": "EOS has no sudo, so there is no password to give it. Remove become_password_file from this ssh block.",
	} {
		v := conn.GetAttr(attr)
		if v.IsNull() || !v.IsKnown() || (v.Type() == cty.Bool && v.False()) {
			continue
		}
		diags = diags.Append(tfdiags.AttributeValue(tfdiags.Error, "Invalid ssh setting for an EOS switch", why,
			cty.GetAttrPath("ssh").GetAttr(attr)))
	}
	if v := optional(conn, "confirm_after"); known(v) {
		if d, err := time.ParseDuration(v.AsString()); err == nil {
			if err := eos.CheckConfirmAfter(d); err != nil {
				diags = diags.Append(tfdiags.AttributeValue(tfdiags.Error, "Invalid ssh confirm_after", err.Error(),
					cty.GetAttrPath("ssh").GetAttr("confirm_after")))
			}
		}
	}
	return diags
}

// validateNotEOS refuses confirm_after on a step that isn't an EOS step:
// nothing else commits with a revert timer, so it would do nothing.
func validateNotEOS(cfg cty.Value) tfdiags.Diagnostics {
	var diags tfdiags.Diagnostics
	if cfg.IsNull() || !cfg.Type().HasAttribute("ssh") {
		return diags
	}
	if conn := cfg.GetAttr("ssh"); !conn.IsNull() && conn.IsKnown() && !optional(conn, "confirm_after").IsNull() {
		diags = diags.Append(tfdiags.AttributeValue(tfdiags.Error, "Invalid ssh setting",
			"confirm_after only applies to eos_* steps, which commit with a revert timer. Remove it from this ssh block, or put the switches in their own circuit.",
			cty.GetAttrPath("ssh").GetAttr("confirm_after")))
	}
	return diags
}

// eosDevice returns the pooled connection to a switch. It never attaches the
// agent, whatever CONN3X_AGENT says.
func eosDevice(ctx context.Context, conn cty.Value) (*hostConn, error) {
	return pooled(ctx, conn, 0)
}

// confirmAfter is the ssh block's confirm_after, already checked by
// validateEOSSSH, or the default.
func confirmAfter(conn cty.Value) time.Duration {
	if d, err := time.ParseDuration(stringOr(optional(conn, "confirm_after"), "")); err == nil {
		return d
	}
	return eos.DefaultConfirmAfter
}

// eosReconnect dials a new connection, outside the pool, for confirming a
// commit: that the login still works is the point.
func eosReconnect(conn cty.Value) func(context.Context) (eos.Device, error) {
	return func(ctx context.Context) (eos.Device, error) {
		cfg, err := sshConfig(conn)
		if err != nil {
			return nil, err
		}
		return ssh.Dial(ctx, cfg)
	}
}

// eosKind is one EOS step module: how to read its wanted lines from a
// resource's state, and what removing it takes, when it can be removed.
type eosKind struct {
	name     string
	keys     []string // changing one of these is a new resource
	settings []string // changing one of these is an update
	deletes  bool     // on_remove defaults to "delete"
	config   func(cty.Value) eosWant
	remove   func(cty.Value, string) []string // nil: removing only forgets
	// guard, when set, refuses a change that would cut Conn3x off from the
	// switch at address, given the config it's computed from.
	guard func(v cty.Value, config, address string) error
	// warn, when set, is what a read has to say about the config, or "".
	warn func(v cty.Value, config string) string
}

// eosWant is what a step wants of a switch's config, such as eos.Config.
type eosWant interface {
	InSync(config string) bool
	Commands(config string) []string
}

func (k eosKind) plan(req providers.PlanResourceChangeRequest) providers.PlanResourceChangeResponse {
	if k.deletes {
		req = deleteByDefault(req)
	}
	return planSynced(req, "eos_"+k.name, k.keys, k.settings)
}

func (k eosKind) read(ctx context.Context, req providers.ReadResourceRequest) providers.ReadResourceResponse {
	resp := providers.ReadResourceResponse{NewState: req.PriorState}
	if req.PriorState.IsNull() {
		return resp
	}
	h, err := eosDevice(ctx, req.PriorState.GetAttr("ssh"))
	if err != nil {
		resp.Diagnostics = resp.Diagnostics.Append(attrError("ssh", err.Error()))
		return resp
	}
	running, err := eos.RunningConfig(ctx, h.client)
	if err != nil {
		resp.Diagnostics = resp.Diagnostics.Append(fmt.Errorf("eos_%s: %w", k.name, err))
		return resp
	}
	resp.NewState = withSync(req.PriorState, k.config(req.PriorState).InSync(running))
	if k.warn != nil {
		if w := k.warn(req.PriorState, running); w != "" {
			resp.Diagnostics = resp.Diagnostics.Append(tfdiags.SimpleWarning(fmt.Sprintf("eos_%s on %s: %s", k.name, h.host, w)))
		}
	}
	return resp
}

// apply adds the step's lines to the switch's session for this run, which
// the circuit's conn3x_eos_commit makes live once every step is in. A step
// with nothing to change opens no session. A removal goes into the session
// when one is open, or when the circuit is being destroyed and its
// conn3x_eos_removals is still to come; otherwise, as for a step dropped
// from a circuit that stays, it commits in a session of its own.
func (k eosKind) apply(ctx context.Context, req providers.ApplyResourceChangeRequest) providers.ApplyResourceChangeResponse {
	var resp providers.ApplyResourceChangeResponse
	fail := func(err error) providers.ApplyResourceChangeResponse {
		resp.Diagnostics = resp.Diagnostics.Append(fmt.Errorf("eos_%s: %w", k.name, err))
		return resp
	}
	target := req.PlannedState
	removing := target.IsNull()
	if removing {
		resp.NewState = target
		if k.remove == nil || req.PriorState.IsNull() || req.PriorState.GetAttr("on_remove").AsString() != onRemoveDelete {
			return resp
		}
		target = req.PriorState
	}
	conn := target.GetAttr("ssh")
	h, err := eosDevice(ctx, conn)
	if err != nil {
		resp.Diagnostics = resp.Diagnostics.Append(attrError("ssh", err.Error()))
		return resp
	}
	circuit := eosCircuit(target)
	st := stagedOn(h)
	unlock, err := st.turn(ctx, h, circuit, lockHost(h, "eos"))
	defer func() { unlock() }()
	if err != nil {
		return fail(err)
	}
	if err := st.failed[circuit]; err != nil {
		return fail(fmt.Errorf("not applied: %w", err))
	}
	defer func() { st.touched = time.Now() }()
	var base string
	if st.session != nil {
		base, err = st.session.Config(ctx, h.client)
	} else {
		base, err = eos.RunningConfig(ctx, h.client)
	}
	if err != nil {
		return fail(st.abort(ctx, h, err))
	}
	var cmds []string
	if removing {
		cmds = k.remove(target, base)
	} else {
		if k.guard != nil {
			if err := k.guard(target, base, h.host); err != nil {
				return fail(st.abort(ctx, h, err))
			}
		}
		cmds = k.config(target).Commands(base)
	}
	switch {
	case len(cmds) == 0:
	case removing && st.session == nil && !st.batch[circuit]:
		diff, err := eos.Apply(ctx, h.client, eosReconnect(conn), base, cmds, confirmAfter(conn))
		if diff != "" {
			log.Printf("[INFO] conn3x: eos_%s on %s: lines added:\n%s", k.name, h.host, eos.Mask(diff))
		}
		if err != nil {
			return fail(err)
		}
	default:
		if st.session == nil {
			if st.session, err = eos.Open(ctx, h.client, base); err != nil {
				return fail(err)
			}
			st.owner = circuit
		}
		if err := st.session.Add(ctx, h.client, cmds); err != nil {
			return fail(st.abort(ctx, h, err))
		}
		if removing {
			st.removals, st.conn = append(st.removals, cmds), conn
		}
	}
	if !removing {
		resp.NewState = withSync(req.PlannedState, true)
	}
	return resp
}

// staged is the config session one switch's steps are adding to in this
// run. The built-in provider runs in-process, so every step and commit of
// a run sees the same one. Callers hold lockHost(h, "eos").
type staged struct {
	h        *hostConn
	session  *eos.Session     // nil: nothing staged yet
	failed   map[string]error // by circuit: its session was aborted, and nothing more of it goes in
	removals [][]string       // removals in the session: their steps are already forgotten
	conn     cty.Value        // the ssh block they came with, to commit them again
	// owner is the circuit whose steps opened the session, "" for steps
	// outside a circuit. A switch has one session at a time, so until the
	// owner's commit, or an abort, other circuits' steps wait: a commit
	// then makes live one circuit's lines and nobody else's.
	owner   string
	touched time.Time       // when the owner last added to the session or finished a step
	batch   map[string]bool // circuits being destroyed: their removals stage for conn3x_eos_removals
	// committed: a commit already made lines live in this run.
	committed bool
}

// eosTurnIdle is how long a circuit's steps wait for another circuit that
// has lines staged on the switch and does nothing with them. That circuit
// has most likely stopped at an error of its own, short of its commit. It
// measures quiet, not stuck: the provider can't see whether the owner has a
// step still to come, so an owner waiting on something slow elsewhere looks
// the same.
var eosTurnIdle = 2 * time.Minute

// eosCircuitAttr is how a step, a commit or the removals know their circuit.
func eosCircuitAttr() *configschema.Attribute {
	return &configschema.Attribute{Type: cty.String, Optional: true, Description: "The circuit this belongs to. Circuits set it: a switch's config session holds one circuit's lines at a time."}
}

func eosCircuit(v cty.Value) string {
	if c := v.GetAttr("circuit"); known(c) {
		return c.AsString()
	}
	return ""
}

// turn waits until the switch has no session of another circuit's. The
// caller holds lockHost(h, "eos") through unlock, which turn gives up
// while it waits; it returns the unlock to call in the end.
func (st *staged) turn(ctx context.Context, h *hostConn, circuit string, unlock func()) (func(), error) {
	for st.session != nil && st.owner != circuit {
		if idle := time.Since(st.touched); idle > eosTurnIdle {
			return unlock, fmt.Errorf("not applied: circuit %q has lines waiting on %s that it has neither committed nor added to for %s, so this circuit's turn on the switch never came. %q may have stopped at an error, or its next step may be waiting on something slow that isn't on the switch. Apply again once it has committed or its error is fixed", st.owner, h.host, eosTurnIdle, st.owner)
		}
		unlock()
		select {
		case <-ctx.Done():
			return func() {}, ctx.Err()
		case <-time.After(eosTurnPoll):
		}
		unlock = lockHost(h, "eos")
	}
	return unlock, nil
}

const eosTurnPoll = 50 * time.Millisecond

var stagedSessions = struct {
	sync.Mutex
	m map[string]*staged // rootKey
}{m: map[string]*staged{}}

func stagedOn(h *hostConn) *staged {
	stagedSessions.Lock()
	defer stagedSessions.Unlock()
	st, ok := stagedSessions.m[h.rootKey]
	if !ok {
		st = &staged{h: h}
		stagedSessions.m[h.rootKey] = st
	}
	return st
}

// abort drops the session after err, and every line staged with it, and
// marks its circuit failed on the switch for the rest of the run. With
// nothing staged, it returns err as it is. Removals in it are made live on
// their own, since their steps are already gone from state.
func (st *staged) abort(ctx context.Context, h *hostConn, err error) error {
	if st.session == nil {
		return err
	}
	if abortErr := st.session.Abort(ctx, h.client); abortErr != nil {
		err = fmt.Errorf("%w; %v", err, abortErr)
	} else {
		if st.committed {
			err = fmt.Errorf("%w. The lines steps added since this apply's last commit on %s were dropped too; what earlier commits made live stays", err, h.host)
		} else {
			err = fmt.Errorf("%w. Nothing was changed on %s: the lines earlier steps added in this apply were dropped too", err, h.host)
		}
		err, _ = st.salvage(ctx, h, st.removals, err)
	}
	if st.failed == nil {
		st.failed = map[string]error{}
	}
	st.session, st.removals, st.failed[st.owner] = nil, nil, err
	return err
}

// salvage commits removed, the removals of a session that went nowhere, in
// a session of their own: OpenTofu has already forgotten their steps, so
// the switch must lose those lines too. It returns err, saying what became
// of them, and whether the switch still has them.
func (st *staged) salvage(ctx context.Context, h *hostConn, removed [][]string, err error) (_ error, left bool) {
	if len(removed) == 0 {
		return err, false
	}
	var lines []string
	for _, cmds := range removed {
		lines = append(lines, strings.Join(cmds, "; "))
	}
	if errors.As(err, new(eos.SessionGoneError)) {
		// Another run has the switch; a session of ours would abort its.
		return fmt.Errorf("%w. Removals in that session were dropped as well, and Conn3x has already forgotten them, so once the other run is done, remove these by hand: %s", err, strings.Join(lines, " | ")), true
	}
	again := func() error {
		running, err := eos.RunningConfig(ctx, h.client)
		if err != nil {
			return err
		}
		s, err := eos.Open(ctx, h.client, running)
		if err != nil {
			return err
		}
		for _, cmds := range removed {
			if err := s.Add(ctx, h.client, cmds); err != nil {
				_ = s.Abort(ctx, h.client)
				return err
			}
		}
		_, err = s.Commit(ctx, h.client, eosReconnect(st.conn), confirmAfter(st.conn))
		return err
	}
	if againErr := again(); againErr != nil {
		return fmt.Errorf("%w. Removals in that session were dropped as well, and committing them on their own failed too (%v). Conn3x has already forgotten them, so remove these by hand: %s", err, againErr, strings.Join(lines, " | ")), true
	}
	return fmt.Errorf("%w. The removals in that session were committed on their own, so the switch no longer has them: %s", err, strings.Join(lines, " | ")), false
}

// abortStaged aborts every session still staged, as when a run fails
// before a switch's commit. The sessions were never live. What that leaves
// for someone to do by hand goes to stagedLeft: a session it couldn't
// abort, and removals the switch still has though their steps are gone
// from state.
func abortStaged() {
	stagedSessions.Lock()
	defer stagedSessions.Unlock()
	for key, st := range stagedSessions.m {
		if st.session != nil {
			ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
			log.Printf("[WARN] conn3x: aborting config session %s on %s, which no conn3x_eos_commit made live", st.session.Name, st.h.host)
			if err := st.session.Abort(ctx, st.h.client); err != nil {
				log.Printf("[WARN] conn3x: %v", err)
				stagedLeft = append(stagedLeft, fmt.Errorf("%s: %w", st.h.host, err))
			} else if len(st.removals) > 0 {
				// Up to five minutes: a commit, its wait and the confirm.
				cancel()
				ctx, cancel = context.WithTimeout(context.Background(), eos.RevertAfter)
				err, left := st.salvage(ctx, st.h, st.removals, fmt.Errorf("the run stopped before the commit"))
				log.Printf("[WARN] conn3x: %v", err)
				if left {
					stagedLeft = append(stagedLeft, fmt.Errorf("%s: %w", st.h.host, err))
				}
			}
			cancel()
		}
		delete(stagedSessions.m, key)
	}
}

// stagedLeft is what abortStaged couldn't clean up. Guarded by
// stagedSessions.
var stagedLeft []error

// FinishEOS ends a run for the EOS steps: it aborts what is still staged and
// returns what that left on a switch, for the command to print. A failed
// apply doesn't close its providers, so the command calls this as it exits.
func FinishEOS() error {
	abortStaged()
	stagedSessions.Lock()
	defer stagedSessions.Unlock()
	err := errors.Join(stagedLeft...)
	stagedLeft = nil
	return err
}

// openProviders counts provider instances not yet closed. The last Close
// aborts what is still staged.
var openProviders atomic.Int64

func (k eosKind) entry(schema func() providers.Schema, validate func(cty.Value) tfdiags.Diagnostics) resourceType {
	return resourceType{schema, validate, k.plan, k.read, k.apply, upgradeWith(schema)}
}

func stringList(v cty.Value) []string {
	if v.IsNull() || !v.IsKnown() {
		return nil
	}
	var out []string
	for _, e := range v.AsValueSlice() {
		out = append(out, e.AsString())
	}
	return out
}

func eosConfigFrom(v cty.Value) eos.Config {
	return eos.Config{Parents: stringList(v.GetAttr("parents")), Lines: stringList(v.GetAttr("lines")), Match: stringOr(v.GetAttr("match"), eos.MatchLines)}
}

var eosConfigKind = eosKind{
	name:     "config",
	keys:     []string{"parents"},
	settings: []string{"lines", "match"},
	config:   func(v cty.Value) eosWant { return eosConfigFrom(v) },
	remove:   func(v cty.Value, running string) []string { return eosConfigFrom(v).RemoveCommands(running) },
}

func eosConfigSchema() providers.Schema {
	return providers.Schema{Block: &configschema.Block{
		Description: eosExperimental + "Lines of an Arista EOS switch's configuration, under a parent block such as an interface. Only the lines named here are owned; with match = \"block\" the block must hold exactly these.",
		Attributes: map[string]*configschema.Attribute{
			"id":        {Type: cty.String, Computed: true},
			"revision":  revisionAttr(),
			"parents":   {Type: cty.List(cty.String), Optional: true, Description: "The block the lines go under, outermost first, as show running-config prints it, such as [\"interface Ethernet1\"] or [\"router bgp 65000\", \"address-family ipv4\"]. Leave unset for top-level lines."},
			"lines":     {Type: cty.List(cty.String), Optional: true, Description: "The lines, as show running-config prints them, without the indent. The switch must print a line back exactly as written, or it never shows as in sync."},
			"match":     {Type: cty.String, Optional: true, Description: "\"lines\" (default): these lines must be there, and others under the parent are left alone. \"block\": the block must be exactly these lines, so others under it are removed. Needs parents."},
			"on_remove": {Type: cty.String, Optional: true, Computed: true, Description: "What happens on the switch when this resource is removed: \"forget\" (default) leaves the lines, \"delete\" removes them with \"no\" and leaves the parent."},
			"in_sync":   {Type: cty.Bool, Computed: true, Description: "Whether the switch had these lines at the last refresh."},
			"circuit":   eosCircuitAttr(),
		},
		BlockTypes: map[string]*configschema.NestedBlock{"ssh": connectionBlock()},
	}}
}

func validateEOSConfig(cfg cty.Value) tfdiags.Diagnostics {
	var diags tfdiags.Diagnostics
	if cfg.IsNull() || !cfg.IsWhollyKnown() {
		return diags
	}
	diags = diags.Append(validateOnRemove(cfg))
	if err := eosConfigFrom(cfg).Validate(); err != nil {
		diags = diags.Append(attrError("lines", err.Error()))
	}
	return diags
}

var eosHostnameKind = eosKind{
	name:     "hostname",
	settings: []string{"name"},
	config:   func(v cty.Value) eosWant { return eos.Hostname(v.GetAttr("name").AsString()) },
}

func eosHostnameSchema() providers.Schema {
	s := singletonSchema(eosExperimental+"An Arista EOS switch's hostname. Removing this step leaves the name as it is.",
		"Hostname, such as leaf1. EOS takes letters, digits, hyphens and dots.")
	s.Block.Attributes["in_sync"].Description = "Whether the switch had this name at the last refresh."
	s.Block.Attributes["circuit"] = eosCircuitAttr()
	return s
}

func validateEOSHostname(cfg cty.Value) tfdiags.Diagnostics {
	return validateName(cfg, eos.ValidateHostname)
}

func eosVLANFrom(v cty.Value) eos.VLAN {
	id, _ := v.GetAttr("vlan_id").AsBigFloat().Int64()
	return eos.VLAN{ID: int(id), Name: stringOr(v.GetAttr("name"), "")}
}

var eosVLANKind = eosKind{
	name:     "vlan",
	keys:     []string{"vlan_id"},
	settings: []string{"name"},
	deletes:  true,
	config:   func(v cty.Value) eosWant { return eosVLANFrom(v) },
	remove:   func(v cty.Value, running string) []string { return eosVLANFrom(v).RemoveCommands(running) },
}

func eosVLANSchema() providers.Schema {
	return providers.Schema{Block: &configschema.Block{
		Description: eosExperimental + "A VLAN on an Arista EOS switch, and its name.",
		Attributes: map[string]*configschema.Attribute{
			"id":        {Type: cty.String, Computed: true},
			"revision":  revisionAttr(),
			"vlan_id":   {Type: cty.Number, Required: true, Description: "VLAN ID, 1 to 4094."},
			"name":      {Type: cty.String, Optional: true, Description: "VLAN name: one word, up to 32 characters. Leave unset for the switch's default, such as VLAN0010; a name set by hand is then removed."},
			"on_remove": {Type: cty.String, Optional: true, Computed: true, Description: "What happens on the switch when this resource is removed: \"delete\" (default) removes the VLAN, \"forget\" leaves it."},
			"in_sync":   {Type: cty.Bool, Computed: true, Description: "Whether the VLAN was there, with this name, at the last refresh."},
			"circuit":   eosCircuitAttr(),
		},
		BlockTypes: map[string]*configschema.NestedBlock{"ssh": connectionBlock()},
	}}
}

func validateEOSVLAN(cfg cty.Value) tfdiags.Diagnostics {
	return validateWith("vlan_id", func(v cty.Value) error { return eosVLANFrom(v).Validate() })(cfg)
}

// eosDeviceSchema is the conn3x_eos_device data source: what a circuit
// checks before it changes a switch.
func eosDeviceSchema() providers.Schema {
	return providers.Schema{Block: &configschema.Block{
		Description: eosExperimental + "Facts about an Arista EOS switch, from show version and show hostname.",
		Attributes: map[string]*configschema.Attribute{
			"hostname":   {Type: cty.String, Computed: true, Description: "The switch's hostname."},
			"model":      {Type: cty.String, Computed: true, Description: "Model, such as DCS-7050SX3-48YC8, or cEOSLab."},
			"version":    {Type: cty.String, Computed: true, Description: "EOS version as show version prints it, such as 4.37.0F or 4.37.0F-51574443.4370F.1 (engineering build)."},
			"serial":     {Type: cty.String, Computed: true, Description: "Serial number. cEOS-lab reports a made-up one."},
			"system_mac": {Type: cty.String, Computed: true, Description: "System MAC address."},
		},
		BlockTypes: map[string]*configschema.NestedBlock{"ssh": connectionBlock()},
	}}
}

func readEOSDevice(ctx context.Context, req providers.ReadDataSourceRequest) providers.ReadDataSourceResponse {
	var resp providers.ReadDataSourceResponse
	h, err := eosDevice(ctx, req.Config.GetAttr("ssh"))
	if err != nil {
		resp.Diagnostics = resp.Diagnostics.Append(attrError("ssh", err.Error()))
		return resp
	}
	f, err := eos.ReadFacts(ctx, h.client)
	if err != nil {
		resp.Diagnostics = resp.Diagnostics.Append(fmt.Errorf("conn3x_eos_device: %w", err))
		return resp
	}
	vals := req.Config.AsValueMap()
	vals["hostname"] = cty.StringVal(f.Hostname)
	vals["model"] = cty.StringVal(f.Model)
	vals["version"] = cty.StringVal(f.Version)
	vals["serial"] = cty.StringVal(f.Serial)
	vals["system_mac"] = cty.StringVal(f.SystemMAC)
	resp.State = cty.ObjectVal(vals)
	return resp
}

// conn3x_eos_commit makes live what a circuit's eos_* steps staged on one
// switch. It isn't a step module: the circuit lowering adds one per circuit
// with eos steps, after all of them, with their revisions as triggers, so it
// plans a change exactly when one of them does.
func eosCommitSchema() providers.Schema {
	return providers.Schema{Block: &configschema.Block{
		Description: eosExperimental + "Commits the config session a circuit's eos_* steps added their lines to, with a revert timer, waits confirm_after, confirms over a new login and saves. Circuits add it; it isn't a step.",
		Attributes: map[string]*configschema.Attribute{
			"id":       {Type: cty.String, Computed: true},
			"triggers": {Type: cty.DynamicPseudoType, Optional: true, Description: "The revisions of the circuit's eos steps on this switch; the commit runs when they change."},
			"removals": {Type: cty.String, Optional: true, Description: "The id of the circuit's conn3x_eos_removals on this switch. With one, destroying the circuit stages the steps' removals for it to commit once."},
			"circuit":  eosCircuitAttr(),
		},
		BlockTypes: map[string]*configschema.NestedBlock{"ssh": connectionBlock()},
	}}
}

func planEOSCommit(req providers.PlanResourceChangeRequest) providers.PlanResourceChangeResponse {
	var resp providers.PlanResourceChangeResponse
	if req.ProposedNewState.IsNull() {
		resp.PlannedState = req.ProposedNewState
		return resp
	}
	vals := req.ProposedNewState.AsValueMap()
	vals["id"] = planID(req, "eos-commit")
	resp.PlannedState = cty.ObjectVal(vals)
	return resp
}

// readEOSCommit keeps state as it is: the steps are what drift.
func readEOSCommit(_ context.Context, req providers.ReadResourceRequest) providers.ReadResourceResponse {
	return providers.ReadResourceResponse{NewState: req.PriorState}
}

func applyEOSCommit(ctx context.Context, req providers.ApplyResourceChangeRequest) providers.ApplyResourceChangeResponse {
	resp := providers.ApplyResourceChangeResponse{NewState: req.PlannedState}
	destroying := req.PlannedState.IsNull()
	if destroying && req.PriorState.GetAttr("removals").IsNull() {
		return resp // lowered before conn3x_eos_removals: each removal commits on its own
	}
	obj := req.PlannedState
	if destroying {
		obj = req.PriorState
	}
	conn := obj.GetAttr("ssh")
	h, err := eosDevice(ctx, conn)
	if err != nil {
		resp.Diagnostics = resp.Diagnostics.Append(attrError("ssh", err.Error()))
		return resp
	}
	defer lockHost(h, "eos")()
	st := stagedOn(h)
	circuit := eosCircuit(obj)
	if destroying {
		// The steps' removals come next, then conn3x_eos_removals commits them.
		if st.batch == nil {
			st.batch = map[string]bool{}
		}
		st.batch[circuit] = true
		return resp
	}
	if err := st.failed[circuit]; err != nil {
		resp.Diagnostics = resp.Diagnostics.Append(fmt.Errorf("eos commit: nothing was committed: %w", err))
		return resp
	}
	if st.session == nil || st.owner != circuit {
		return resp // no step of this circuit changed anything on this switch
	}
	s, removed := st.session, st.removals
	st.session, st.removals = nil, nil // committed or rolling back: either way, gone
	diff, err := s.Commit(ctx, h.client, eosReconnect(conn), confirmAfter(conn))
	if diff != "" {
		log.Printf("[INFO] conn3x: eos commit on %s: lines added:\n%s", h.host, eos.Mask(diff))
	}
	if errors.As(err, new(eos.NotLiveError)) {
		err, _ = st.salvage(ctx, h, removed, err)
	}
	st.committed = st.committed || err == nil
	if err != nil {
		resp.Diagnostics = resp.Diagnostics.Append(fmt.Errorf("eos commit: %w. The steps are recorded as applied, so the next refresh finds them out of sync and the next apply makes them again", err))
	}
	return resp
}

// conn3x_eos_removals commits, once per switch, what a destroyed circuit's
// steps removed. The circuit lowering puts one before every eos step, so a
// destroy reaches it after all of them. Creating or updating it does nothing.
func eosRemovalsSchema() providers.Schema {
	return providers.Schema{Block: &configschema.Block{
		Description: eosExperimental + "Commits, once, the removals a destroyed circuit's eos_* steps added to the switch's config session. Circuits add it; it isn't a step.",
		Attributes:  map[string]*configschema.Attribute{"id": {Type: cty.String, Computed: true}, "circuit": eosCircuitAttr()},
		BlockTypes:  map[string]*configschema.NestedBlock{"ssh": connectionBlock()},
	}}
}

func planEOSRemovals(req providers.PlanResourceChangeRequest) providers.PlanResourceChangeResponse {
	var resp providers.PlanResourceChangeResponse
	if req.ProposedNewState.IsNull() {
		resp.PlannedState = req.ProposedNewState
		return resp
	}
	vals := req.ProposedNewState.AsValueMap()
	vals["id"] = planID(req, "eos-removals")
	resp.PlannedState = cty.ObjectVal(vals)
	return resp
}

func applyEOSRemovals(ctx context.Context, req providers.ApplyResourceChangeRequest) providers.ApplyResourceChangeResponse {
	resp := providers.ApplyResourceChangeResponse{NewState: req.PlannedState}
	if !req.PlannedState.IsNull() {
		return resp
	}
	conn := req.PriorState.GetAttr("ssh")
	h, err := eosDevice(ctx, conn)
	if err != nil {
		resp.Diagnostics = resp.Diagnostics.Append(attrError("ssh", err.Error()))
		return resp
	}
	defer lockHost(h, "eos")()
	st := stagedOn(h)
	circuit := eosCircuit(req.PriorState)
	delete(st.batch, circuit) // a removal after this, out of order, commits on its own
	if err := st.failed[circuit]; err != nil {
		resp.Diagnostics = resp.Diagnostics.Append(fmt.Errorf("eos removals: nothing was committed: %w", err))
		return resp
	}
	if st.session == nil || st.owner != circuit {
		return resp
	}
	s, removed := st.session, st.removals
	st.session, st.removals = nil, nil
	diff, err := s.Commit(ctx, h.client, eosReconnect(conn), confirmAfter(conn))
	if diff != "" {
		log.Printf("[INFO] conn3x: eos removals on %s: lines added:\n%s", h.host, eos.Mask(diff))
	}
	switch {
	case errors.As(err, new(eos.NotLiveError)):
		err, _ = st.salvage(ctx, h, removed, err)
		resp.Diagnostics = resp.Diagnostics.Append(fmt.Errorf("eos removals: %w", err))
	case err != nil:
		var lines []string
		for _, cmds := range removed {
			lines = append(lines, strings.Join(cmds, "; "))
		}
		resp.Diagnostics = resp.Diagnostics.Append(fmt.Errorf("eos removals: %w. Conn3x has already forgotten the removed steps, so if the switch rolls the change back, remove these from %s by hand: %s", err, h.host, strings.Join(lines, " | ")))
	}
	return resp
}

func eosInterfaceFrom(v cty.Value) eos.Interface {
	i := eos.Interface{Name: stringOr(v.GetAttr("name"), ""), Description: optString(v.GetAttr("description")), Mode: stringOr(v.GetAttr("mode"), "")}
	if e := v.GetAttr("enabled"); known(e) {
		b := e.True()
		i.Enabled = &b
	}
	num := func(attr string) int {
		n := v.GetAttr(attr)
		if !known(n) {
			return 0
		}
		x, _ := n.AsBigFloat().Int64()
		return int(x)
	}
	i.AccessVLAN, i.MTU = num("access_vlan"), num("mtu")
	if l := v.GetAttr("allowed_vlans"); known(l) {
		i.AllowedVLANs = []int{}
		for _, e := range l.AsValueSlice() {
			x, _ := e.AsBigFloat().Int64()
			i.AllowedVLANs = append(i.AllowedVLANs, int(x))
		}
	}
	return i
}

var eosInterfaceKind = eosKind{
	name:     "interface",
	keys:     []string{"name"},
	settings: []string{"description", "enabled", "mode", "access_vlan", "allowed_vlans", "mtu"},
	config:   func(v cty.Value) eosWant { return eosInterfaceFrom(v) },
	remove:   func(v cty.Value, running string) []string { return eosInterfaceFrom(v).RemoveCommands(running) },
	guard:    func(v cty.Value, config, address string) error { return eosInterfaceFrom(v).Guard(config, address) },
}

func eosInterfaceSchema() providers.Schema {
	return providers.Schema{Block: &configschema.Block{
		Description: eosExperimental + "The settings Conn3x owns on one interface of an Arista EOS switch: description, enabled, switchport mode and VLANs, MTU. Each one left unset is left alone, and so is every other line under the interface.",
		Attributes: map[string]*configschema.Attribute{
			"id":            {Type: cty.String, Computed: true},
			"revision":      revisionAttr(),
			"name":          {Type: cty.String, Required: true, Description: "The interface, as running-config names it, such as Ethernet1, Ethernet1/1, Port-Channel10, Vlan20 or Loopback0."},
			"description":   {Type: cty.String, Optional: true, Description: "Its description."},
			"enabled":       {Type: cty.Bool, Optional: true, Description: "false shuts it down, true brings it up. Shutting down the interface whose address Conn3x connects to is refused."},
			"mode":          {Type: cty.String, Optional: true, Description: "\"access\" or \"trunk\". Ethernet and Port-Channel interfaces only."},
			"access_vlan":   {Type: cty.Number, Optional: true, Description: "The VLAN of an access port, 1 to 4094."},
			"allowed_vlans": {Type: cty.List(cty.Number), Optional: true, Description: "The VLANs a trunk carries. Conn3x writes them the way EOS prints them, as in 10,20-22."},
			"mtu":           {Type: cty.Number, Optional: true, Description: "MTU, 68 to 9214."},
			"on_remove":     {Type: cty.String, Optional: true, Computed: true, Description: "What happens when this resource is removed: \"forget\" (default) leaves the interface as it is, \"delete\" takes the settings it owns back to EOS's defaults. The interface itself stays."},
			"in_sync":       {Type: cty.Bool, Computed: true, Description: "Whether the interface had these settings at the last refresh."},
			"circuit":       eosCircuitAttr(),
		},
		BlockTypes: map[string]*configschema.NestedBlock{"ssh": connectionBlock()},
	}}
}

func validateEOSInterface(cfg cty.Value) tfdiags.Diagnostics {
	var diags tfdiags.Diagnostics
	if cfg.IsNull() || !cfg.IsWhollyKnown() {
		return diags
	}
	diags = diags.Append(validateOnRemove(cfg))
	if err := eosInterfaceFrom(cfg).Validate(); err != nil {
		diags = diags.Append(attrError("name", err.Error()))
	}
	return diags
}

func eosUserFrom(v cty.Value) eos.User {
	u := eos.User{Name: stringOr(v.GetAttr("name"), ""), Privilege: -1, Role: stringOr(v.GetAttr("role"), ""), SSHKey: optString(v.GetAttr("ssh_key"))}
	if p := v.GetAttr("privilege"); known(p) {
		n, _ := p.AsBigFloat().Int64()
		u.Privilege = int(n)
	}
	if n := v.GetAttr("nopassword"); known(n) {
		b := n.True()
		u.NoPassword = &b
	}
	// password_hmac is unknown while a new password is planned.
	stored := v.GetAttr("password_hmac")
	u.WantSecret = !stored.IsNull()
	// Without the key that made password_hmac, as on a machine that only
	// refreshes or destroys, a read can't tell which secret the switch
	// holds, only that it has one. A plan with password_wo fails on the key.
	if key, err := hmacKey(false); err == nil && known(stored) && checkHMACKey(stored.AsString(), key) == nil {
		id := eosUserID(v)
		u.SecretIs = func(hash string) bool {
			return hmac.Equal([]byte(eosSecretHMAC(key, id, hash)), []byte(stored.AsString()))
		}
	}
	return u
}

func eosUserID(v cty.Value) string {
	return passwordID("eos_user", stringOr(v.GetAttr("ssh").GetAttr("host"), ""), stringOr(v.GetAttr("name"), ""))
}

// eosSecret is the hash eos_user sends for password, "$6$<salt>$<hash>". Its
// salt comes from the key and the stretched password, so the same password
// always gives the same hash, and a plan can say what a read should find.
func eosSecret(key []byte, id, password string) string {
	salt := hmac.New(sha256.New, key)
	salt.Write([]byte("conn3x eos salt\x00" + passwordHMAC(key, id, password)))
	return eos.SecretHash(password, eos.CryptSalt(salt.Sum(nil)))
}

// eosSecretHMAC is what password_hmac records: an HMAC of the hash the
// switch should hold. State keeps neither the password nor the hash, and a
// guess at the password still costs the Argon2id stretch behind the salt.
func eosSecretHMAC(key []byte, id, hash string) string {
	return passwordTag + contentHMAC(key, id, "eos secret:"+hash)
}

func eosPasswordHMAC(key []byte, id, password string) string {
	return eosSecretHMAC(key, id, eosSecret(key, id, password))
}

var eosUserKind = eosKind{
	name:     "user",
	keys:     []string{"name"},
	settings: []string{"privilege", "role", "ssh_key", "nopassword", "password_hmac"},
	deletes:  true,
	config:   func(v cty.Value) eosWant { return eosUserFrom(v) },
	remove:   func(v cty.Value, running string) []string { return eosUserFrom(v).RemoveCommands(running) },
	guard: func(v cty.Value, _, _ string) error {
		return eosUserFrom(v).Guard(stringOr(v.GetAttr("ssh").GetAttr("user"), ""))
	},
	warn: func(v cty.Value, config string) string {
		u := eosUserFrom(v)
		if !u.OpenLogin(config) {
			return ""
		}
		return fmt.Sprintf("account %s has nopassword, so it logs in with an empty password wherever the switch takes password logins, the console included. Conn3x up to v0.11.0 made key-only accounts this way. Set nopassword = false to give it a secret no password matches, password_wo to give it a password, or nopassword = true to keep it and stop this warning.", u.Name)
	},
}

func eosUserSchema() providers.Schema {
	return providers.Schema{Block: &configschema.Block{
		Description: eosExperimental + "A local account on an Arista EOS switch: its privilege, role, password and SSH key. Settings left unset are left alone. Conn3x won't demote or delete the account it logs in as.",
		Attributes: map[string]*configschema.Attribute{
			"id":            {Type: cty.String, Computed: true},
			"revision":      revisionAttr(),
			"name":          {Type: cty.String, Required: true, Description: "The user name."},
			"privilege":     {Type: cty.Number, Optional: true, Description: "0 to 15. Conn3x's own login needs 15."},
			"role":          {Type: cty.String, Optional: true, Description: "A role, such as network-admin or network-operator."},
			"password_wo":   {Type: cty.String, Optional: true, Sensitive: true, WriteOnly: true, Description: "Write-only: the password, never kept in state. Conn3x hashes it here and sends the switch the salted hash it would store anyway, so the password itself never reaches the CLI; a new value plans a change through password_hmac. Unset leaves the account's password alone, and a new account gets a secret no password matches (secret *), for SSH keys only."},
			"nopassword":    {Type: cty.Bool, Optional: true, Description: "true lets the account log in with no password at all (nopassword), wherever the switch takes password logins. false makes sure it can't: an account that has nopassword gets a secret no password matches. Unset leaves an existing account as it is. Can't be true with password_wo."},
			"password_hmac": {Type: cty.String, Computed: true, Description: "An HMAC of the salted hash the switch should hold for password_wo, keyed outside state. A new password plans a change, and a refresh finds an account whose secret is another one out of sync."},
			"ssh_key":       {Type: cty.String, Optional: true, Description: "One public key line, such as \"ssh-ed25519 AAAA... alice@laptop\". \"\" removes the account's key."},
			"on_remove":     {Type: cty.String, Optional: true, Computed: true, Description: "\"delete\" (default) removes the account when the step goes, as with every step that grants access; \"forget\" leaves it."},
			"in_sync":       {Type: cty.Bool, Computed: true, Description: "Whether the account matched at the last refresh."},
			"circuit":       eosCircuitAttr(),
		},
		BlockTypes: map[string]*configschema.NestedBlock{"ssh": connectionBlock()},
	}}
}

func validateEOSUser(cfg cty.Value) tfdiags.Diagnostics {
	var diags tfdiags.Diagnostics
	if cfg.IsNull() || !cfg.IsWhollyKnown() {
		return diags
	}
	diags = diags.Append(validateOnRemove(cfg))
	u := eosUserFrom(cfg)
	u.WantSecret = !cfg.GetAttr("password_wo").IsNull()
	if err := u.Validate(); err != nil {
		diags = diags.Append(attrError("name", err.Error()))
	}
	return diags
}

func planEOSUser(req providers.PlanResourceChangeRequest) providers.PlanResourceChangeResponse {
	return planPasswordAs(deleteByDefault(req), "eos_user", eosUserKind.settings, planSyncedFold, eosPasswordHMAC)
}

// applyEOSUser hashes the step's password, which only the config holds, for
// the commands. They send the hash whenever the switch holds another one,
// whatever state says: an account that was already there, or a password
// whose session never committed, has the old secret.
func applyEOSUser(ctx context.Context, req providers.ApplyResourceChangeRequest) providers.ApplyResourceChangeResponse {
	if req.PlannedState.IsNull() && !req.PriorState.IsNull() && req.PriorState.GetAttr("on_remove").AsString() == onRemoveDelete {
		if name := req.PriorState.GetAttr("name").AsString(); name == stringOr(req.PriorState.GetAttr("ssh").GetAttr("user"), "") {
			var resp providers.ApplyResourceChangeResponse
			resp.Diagnostics = resp.Diagnostics.Append(fmt.Errorf("eos_user: Conn3x logs in as %s, so it won't delete that account; set on_remove = \"forget\" to drop the step", name))
			return resp
		}
	}
	k := eosUserKind
	var mac string
	if !req.PlannedState.IsNull() && eosUserFrom(req.PlannedState).WantSecret {
		var resp providers.ApplyResourceChangeResponse
		password := ""
		if !req.Config.IsNull() {
			password = stringOr(req.Config.GetAttr("password_wo"), "")
		}
		if password == "" {
			resp.Diagnostics = resp.Diagnostics.Append(errors.New("eos_user: password_wo didn't reach the apply; it's write-only, so set it in the step's config"))
			return resp
		}
		key, err := hmacKey(true)
		if err != nil {
			resp.Diagnostics = resp.Diagnostics.Append(attrError("password_wo", err.Error()))
			return resp
		}
		id := eosUserID(req.PlannedState)
		hash := eosSecret(key, id, password)
		mac = eosSecretHMAC(key, id, hash)
		k.config = func(v cty.Value) eosWant {
			u := eosUserFrom(v)
			u.Secret, u.SecretIs = hash, func(h string) bool { return h == hash }
			return u
		}
	}
	resp := k.apply(ctx, req)
	if !resp.NewState.IsNull() {
		vals := resp.NewState.AsValueMap()
		vals["password_wo"] = cty.NullVal(cty.String)
		if mac != "" {
			vals["password_hmac"] = cty.StringVal(mac) // unknown in a plan that didn't know the password
		}
		resp.NewState = cty.ObjectVal(vals)
	}
	return resp
}
