// Copyright (c) The Conn3x Authors
// SPDX-License-Identifier: MPL-2.0

package provider

import (
	"context"
	"errors"
	"fmt"
	"log"
	"time"

	"github.com/zclconf/go-cty/cty"

	"github.com/opentofu/opentofu/internal/conn3x/modules/ios"
	"github.com/opentofu/opentofu/internal/conn3x/modules/junos"
	"github.com/opentofu/opentofu/internal/conn3x/modules/setcfg"
	"github.com/opentofu/opentofu/internal/conn3x/modules/vyos"
	"github.com/opentofu/opentofu/internal/conn3x/transport/ssh"
	"github.com/opentofu/opentofu/internal/providers"
	"github.com/opentofu/opentofu/internal/tfdiags"
)

// cliPlatform is what differs between devices whose configuration is set
// statements, committed with a rollback timer and confirmed over a new
// login: Junos and VyOS, and IOS under its revert timer. cliKind and
// cliStaged do the rest the same way.
type cliPlatform struct {
	name string // "junos", "vyos" or "ios": the step prefix, host lock and log name
	// running reads the configuration as set lines.
	running func(context.Context, cliDevice) (string, error)
	// pending says how the device shows a commit waiting for its confirm,
	// "" when none is; pendingErr is the refusal to change anything then.
	pending    func(context.Context, cliDevice) (string, error)
	pendingErr func(says string) error
	check      func(context.Context, cliDevice, []string) error
	apply      func(ctx context.Context, d cliDevice, reconnect func(context.Context) (*ssh.Client, error), base string, cmds []string, confirmAfter time.Duration) (string, error)
	// notLive reports whether err left nothing live on the device.
	notLive        func(error) bool
	defaultConfirm time.Duration
	revertAfter    time.Duration
	// merge is config once cmds have gone in, for a platform whose
	// configuration isn't set lines; nil is setcfg's.
	merge func(config string, cmds []string) string
	// perCommand is for a device that closes the connection after one
	// session, as IOS XE does: each command gets a connection of its own.
	perCommand bool
}

// cliDevice is what a platform's hooks talk to: the pooled connection, or
// one that dials anew for each command.
type cliDevice interface {
	RunRaw(ctx context.Context, cmd string, stdin []byte) (ssh.Result, error)
	RunShell(ctx context.Context, stdin []byte) (ssh.Result, error)
}

func (p *cliPlatform) device(h *hostConn, conn cty.Value) cliDevice {
	if p.perCommand {
		dial := p.reconnect(conn)
		return ios.PerCommand(func(ctx context.Context) (ios.Device, error) { return dial(ctx) })
	}
	return h.client
}

func (p *cliPlatform) withLines(config string, cmds []string) string {
	if p.merge != nil {
		return p.merge(config, cmds)
	}
	return setcfg.WithLines(config, cmds)
}

func (p *cliPlatform) confirmAfter(conn cty.Value) time.Duration {
	if d, err := time.ParseDuration(stringOr(optional(conn, "confirm_after"), "")); err == nil {
		return d
	}
	return p.defaultConfirm
}

// reconnect dials a new connection, outside the pool, for confirming a
// commit: that the login still works is the point.
func (p *cliPlatform) reconnect(conn cty.Value) func(context.Context) (*ssh.Client, error) {
	return func(ctx context.Context) (*ssh.Client, error) {
		cfg, err := sshConfig(conn)
		if err != nil {
			return nil, err
		}
		return ssh.Dial(ctx, cfg)
	}
}

var junosPlatform = &cliPlatform{
	name:       "junos",
	running:    func(ctx context.Context, c cliDevice) (string, error) { return junos.RunningConfig(ctx, c) },
	pending:    func(ctx context.Context, c cliDevice) (string, error) { return junos.Pending(ctx, c) },
	pendingErr: func(says string) error { return junos.PendingError{Says: says} },
	check:      func(ctx context.Context, c cliDevice, cmds []string) error { return junos.Check(ctx, c, cmds) },
	apply: func(ctx context.Context, c cliDevice, reconnect func(context.Context) (*ssh.Client, error), base string, cmds []string, after time.Duration) (string, error) {
		return junos.Apply(ctx, c, func(ctx context.Context) (junos.Device, error) { return reconnect(ctx) }, base, cmds, after)
	},
	notLive: func(err error) bool {
		return errors.As(err, new(junos.NotLiveError)) || errors.As(err, new(junos.PendingError))
	},
	defaultConfirm: junos.DefaultConfirmAfter,
	revertAfter:    junos.RevertAfter,
}

var vyosPlatform = &cliPlatform{
	name:    "vyos",
	running: func(ctx context.Context, c cliDevice) (string, error) { return vyos.RunningConfig(ctx, c) },
	pending: func(ctx context.Context, c cliDevice) (string, error) {
		if pending, err := vyos.Pending(ctx, c); err != nil || !pending {
			return "", err
		}
		return "commit-confirm.timer is active", nil
	},
	pendingErr: func(string) error { return vyos.ErrPending },
	check:      func(ctx context.Context, c cliDevice, cmds []string) error { return vyos.Check(ctx, c, cmds) },
	apply: func(ctx context.Context, c cliDevice, reconnect func(context.Context) (*ssh.Client, error), base string, cmds []string, after time.Duration) (string, error) {
		return vyos.Apply(ctx, c, func(ctx context.Context) (vyos.Device, error) { return reconnect(ctx) }, base, cmds, after)
	},
	notLive:        func(err error) bool { return errors.As(err, new(vyos.NotLiveError)) },
	defaultConfirm: vyos.DefaultConfirmAfter,
	revertAfter:    vyos.RevertAfter,
}

// cliKind is one step module of a set-statement device. In a circuit its
// steps stage their lines for the circuit's commit; outside one, or when
// dropped from one that stays, a step commits on its own.
type cliKind struct {
	p        *cliPlatform
	name     string
	keys     []string // changing one of these is a new resource
	settings []string // changing one of these is an update
	deletes  bool     // on_remove defaults to "delete"
	config   func(cty.Value) cliWant
	remove   func(cty.Value, string) []string // nil: removing only forgets
	// guard, when set, refuses a change that would cut Conn3x off from the
	// device at address, given the config it's computed from.
	guard func(v cty.Value, config, address string) error
	// warn, when set, is what a refresh has to say about the config, or "".
	warn func(v cty.Value, config string) string
}

// cliWant is what a step wants of a device's configuration.
type cliWant interface {
	InSync(config string) bool
	Commands(config string) []string
}

func (k cliKind) plan(req providers.PlanResourceChangeRequest) providers.PlanResourceChangeResponse {
	if k.deletes {
		req = deleteByDefault(req)
	}
	return planSynced(req, k.p.name+"_"+k.name, k.keys, k.settings)
}

func (k cliKind) read(ctx context.Context, req providers.ReadResourceRequest) providers.ReadResourceResponse {
	resp := providers.ReadResourceResponse{NewState: req.PriorState}
	if req.PriorState.IsNull() {
		return resp
	}
	h, err := pooled(ctx, req.PriorState.GetAttr("ssh"), 0)
	if err != nil {
		resp.Diagnostics = resp.Diagnostics.Append(attrError("ssh", err.Error()))
		return resp
	}
	d := k.p.device(h, req.PriorState.GetAttr("ssh"))
	running, err := k.p.running(ctx, d)
	if err != nil {
		resp.Diagnostics = resp.Diagnostics.Append(fmt.Errorf("%s_%s: %w", k.p.name, k.name, err))
		return resp
	}
	pending, err := k.p.pending(ctx, d)
	if err != nil {
		resp.Diagnostics = resp.Diagnostics.Append(fmt.Errorf("%s_%s: %w", k.p.name, k.name, err))
		return resp
	}
	// Lines an unconfirmed commit added may yet roll back, so they don't count.
	resp.NewState = withSync(req.PriorState, pending == "" && k.config(req.PriorState).InSync(running))
	if pending != "" {
		resp.Diagnostics = resp.Diagnostics.Append(tfdiags.SimpleWarning(fmt.Sprintf("%s_%s on %s: a commit is waiting for its confirm (%s), so this step counts as out of sync until it rolls back", k.p.name, k.name, h.host, pending)))
	}
	if k.warn != nil {
		if w := k.warn(req.PriorState, running); w != "" {
			resp.Diagnostics = resp.Diagnostics.Append(tfdiags.SimpleWarning(fmt.Sprintf("%s_%s on %s: %s", k.p.name, k.name, h.host, w)))
		}
	}
	return resp
}

func (k cliKind) apply(ctx context.Context, req providers.ApplyResourceChangeRequest) providers.ApplyResourceChangeResponse {
	var resp providers.ApplyResourceChangeResponse
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
	h, err := pooled(ctx, conn, 0)
	if err != nil {
		resp.Diagnostics = resp.Diagnostics.Append(attrError("ssh", err.Error()))
		return resp
	}
	fail := func(err error) providers.ApplyResourceChangeResponse {
		resp.Diagnostics = resp.Diagnostics.Append(fmt.Errorf("%s_%s: %w", k.p.name, k.name, err))
		return resp
	}
	circuit := eosCircuit(target)
	st := cliStagedOn(k.p, h)
	// One change at a time on a device.
	unlock, err := st.turn(ctx, h, circuit, lockHost(h, k.p.name))
	defer func() { unlock() }()
	if err != nil {
		return fail(err)
	}
	if err := st.failed[circuit]; err != nil {
		return fail(fmt.Errorf("not applied: %w", err))
	}
	defer func() { st.touched = time.Now() }()
	var view string // what the steps' lines compare with
	if st.cmds != nil {
		view = k.p.withLines(st.base, st.cmds)
	} else {
		// Checked before the lines: with nothing to send, Apply never looks.
		if says, err := k.p.pending(ctx, k.p.device(h, conn)); err != nil || says != "" {
			if err == nil {
				err = k.p.pendingErr(says)
			}
			return fail(err)
		}
		if view, err = k.p.running(ctx, k.p.device(h, conn)); err != nil {
			return fail(err)
		}
	}
	var cmds []string
	if removing {
		cmds = k.remove(target, view)
	} else {
		if k.guard != nil {
			if err := k.guard(target, view, h.host); err != nil {
				return fail(st.drop(ctx, h, circuit, err))
			}
		}
		cmds = k.config(target).Commands(view)
	}
	switch {
	case len(cmds) == 0:
	case circuit == "" || (removing && st.cmds == nil && !st.batch[circuit]):
		// Outside a circuit there's no commit resource to wait for, and a
		// step dropped from a circuit that stays has none coming.
		diff, err := k.p.apply(ctx, k.p.device(h, conn), k.p.reconnect(conn), view, cmds, k.p.confirmAfter(conn))
		if diff != "" {
			log.Printf("[INFO] conn3x: %s_%s on %s: lines sent:\n%s", k.p.name, k.name, h.host, diff)
		}
		if err != nil {
			return fail(err)
		}
	default:
		if err := st.stage(ctx, h, circuit, view, cmds, removing, conn); err != nil {
			return fail(err)
		}
	}
	if !removing {
		resp.NewState = withSync(req.PlannedState, true)
	}
	return resp
}

func (k cliKind) entry(schema func() providers.Schema, validate func(cty.Value) tfdiags.Diagnostics) resourceType {
	return resourceType{schema, validate, k.plan, k.read, k.apply, upgradeWith(schema)}
}
