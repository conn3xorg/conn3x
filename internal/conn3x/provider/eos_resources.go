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
	defer lockHost(h, "eos")()
	st := stagedOn(h)
	if st.failed != nil {
		return fail(fmt.Errorf("not applied: %w", st.failed))
	}
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
	case removing && st.session == nil && !st.batch:
		diff, err := eos.Apply(ctx, h.client, eosReconnect(conn), base, cmds, confirmAfter(conn))
		if diff != "" {
			log.Printf("[INFO] conn3x: eos_%s on %s: session diff:\n%s", k.name, h.host, diff)
		}
		if err != nil {
			return fail(err)
		}
	default:
		if st.session == nil {
			if st.session, err = eos.Open(ctx, h.client, base); err != nil {
				return fail(err)
			}
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
	session  *eos.Session // nil: nothing staged yet
	failed   error        // a step's session was aborted: nothing more goes in
	removals [][]string   // removals in the session: their steps are already forgotten
	conn     cty.Value    // the ssh block they came with, to commit them again
	batch    bool         // destroying: removals stage for conn3x_eos_removals
}

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
// marks the switch failed for the rest of the run. With nothing staged, it
// returns err as it is. Removals in it are made live on their own, since
// their steps are already gone from state.
func (st *staged) abort(ctx context.Context, h *hostConn, err error) error {
	if st.session == nil {
		return err
	}
	if abortErr := st.session.Abort(ctx, h.client); abortErr != nil {
		err = fmt.Errorf("%w; %v", err, abortErr)
	} else {
		err = fmt.Errorf("%w. Nothing was changed on %s: the lines earlier steps added in this apply were dropped too", err, h.host)
		err = st.salvage(ctx, h, st.removals, err)
	}
	st.session, st.removals, st.failed = nil, nil, err
	return err
}

// salvage commits removed, the removals of a session that went nowhere, in
// a session of their own: OpenTofu has already forgotten their steps, so
// the switch must lose those lines too. It returns err, saying what became
// of them.
func (st *staged) salvage(ctx context.Context, h *hostConn, removed [][]string, err error) error {
	if len(removed) == 0 {
		return err
	}
	var lines []string
	for _, cmds := range removed {
		lines = append(lines, strings.Join(cmds, "; "))
	}
	if errors.As(err, new(eos.SessionGoneError)) {
		// Another run has the switch; a session of ours would abort its.
		return fmt.Errorf("%w. Removals in that session were dropped as well, and Conn3x has already forgotten them, so once the other run is done, remove these by hand: %s", err, strings.Join(lines, " | "))
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
		return fmt.Errorf("%w. Removals in that session were dropped as well, and committing them on their own failed too (%v). Conn3x has already forgotten them, so remove these by hand: %s", err, againErr, strings.Join(lines, " | "))
	}
	return fmt.Errorf("%w. The removals in that session were committed on their own, so the switch no longer has them: %s", err, strings.Join(lines, " | "))
}

// abortStaged aborts every session still staged, as when a run fails
// before a switch's commit. The sessions were never live.
func abortStaged() {
	stagedSessions.Lock()
	defer stagedSessions.Unlock()
	for key, st := range stagedSessions.m {
		if st.session != nil {
			ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
			log.Printf("[WARN] conn3x: aborting config session %s on %s, which no conn3x_eos_commit made live", st.session.Name, st.h.host)
			if err := st.session.Abort(ctx, st.h.client); err != nil {
				log.Printf("[WARN] conn3x: %v", err)
			} else if len(st.removals) > 0 {
				// Up to five minutes: a commit, its wait and the confirm.
				cancel()
				ctx, cancel = context.WithTimeout(context.Background(), eos.RevertAfter)
				log.Printf("[WARN] conn3x: %v", st.salvage(ctx, st.h, st.removals, fmt.Errorf("the run stopped before the commit")))
			}
			cancel()
		}
		delete(stagedSessions.m, key)
	}
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
	if destroying {
		// The steps' removals come next, then conn3x_eos_removals commits them.
		st.batch = true
		return resp
	}
	if st.failed != nil {
		resp.Diagnostics = resp.Diagnostics.Append(fmt.Errorf("eos commit: nothing was committed: %w", st.failed))
		return resp
	}
	if st.session == nil {
		return resp // no step changed anything on this switch
	}
	s, removed := st.session, st.removals
	st.session, st.removals = nil, nil // committed or rolling back: either way, gone
	diff, err := s.Commit(ctx, h.client, eosReconnect(conn), confirmAfter(conn))
	if diff != "" {
		log.Printf("[INFO] conn3x: eos commit on %s: session diff:\n%s", h.host, diff)
	}
	if errors.As(err, new(eos.NotLiveError)) {
		err = st.salvage(ctx, h, removed, err)
	}
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
		Attributes:  map[string]*configschema.Attribute{"id": {Type: cty.String, Computed: true}},
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
	st.batch = false // a removal after this, out of order, commits on its own
	if st.failed != nil {
		resp.Diagnostics = resp.Diagnostics.Append(fmt.Errorf("eos removals: nothing was committed: %w", st.failed))
		return resp
	}
	if st.session == nil {
		return resp
	}
	s, removed := st.session, st.removals
	st.session, st.removals = nil, nil
	diff, err := s.Commit(ctx, h.client, eosReconnect(conn), confirmAfter(conn))
	if diff != "" {
		log.Printf("[INFO] conn3x: eos removals on %s: session diff:\n%s", h.host, diff)
	}
	switch {
	case errors.As(err, new(eos.NotLiveError)):
		resp.Diagnostics = resp.Diagnostics.Append(fmt.Errorf("eos removals: %w", st.salvage(ctx, h, removed, err)))
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
