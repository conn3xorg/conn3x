// Copyright (c) The Conn3x Authors
// SPDX-License-Identifier: MPL-2.0

package provider

import (
	"context"
	"errors"
	"time"

	"github.com/zclconf/go-cty/cty"

	"github.com/opentofu/opentofu/internal/configs/configschema"
	"github.com/opentofu/opentofu/internal/conn3x/modules/ios"
	"github.com/opentofu/opentofu/internal/conn3x/transport/ssh"
	"github.com/opentofu/opentofu/internal/providers"
	"github.com/opentofu/opentofu/internal/tfdiags"
)

const (
	iosTypePrefix   = "conn3x_ios_"
	iosExperimental = "Experimental. "
)

var iosPlatform = &cliPlatform{
	name:       "ios",
	running:    func(ctx context.Context, c cliDevice) (string, error) { return ios.RunningConfig(ctx, c) },
	pending:    func(ctx context.Context, c cliDevice) (string, error) { return ios.Pending(ctx, c) },
	pendingErr: func(says string) error { return ios.PendingError{Says: says} },
	check:      func(ctx context.Context, c cliDevice, cmds []string) error { return ios.Check(ctx, c, cmds) },
	apply: func(ctx context.Context, c cliDevice, reconnect func(context.Context) (*ssh.Client, error), base string, cmds []string, after time.Duration) (string, error) {
		return ios.Apply(ctx, c, func(ctx context.Context) (ios.Device, error) { return reconnect(ctx) }, base, cmds, after)
	},
	notLive: func(err error) bool {
		return errors.As(err, new(ios.NotLiveError)) || errors.As(err, new(ios.PendingError))
	},
	defaultConfirm: ios.DefaultConfirmAfter,
	revertAfter:    ios.RevertAfter,
	merge:          ios.WithLines,
	perCommand:     true,
}

var iosCommitTypes = cliCommitTypes(iosPlatform)

// validateIOSSSH rejects the ssh settings an IOS CLI login has no use for.
func validateIOSSSH(cfg cty.Value) tfdiags.Diagnostics {
	var diags tfdiags.Diagnostics
	if cfg.IsNull() || !cfg.Type().HasAttribute("ssh") {
		return diags
	}
	conn := cfg.GetAttr("ssh")
	if conn.IsNull() || !conn.IsKnown() {
		return diags
	}
	for attr, why := range map[string]string{
		"agent":                "The conn3x agent needs a shell, and an IOS login has the CLI instead. Remove agent from this ssh block.",
		"become":               "IOS has no sudo. Log in as a user with privilege 15 (\"username ops privilege 15 ...\"), and remove become from this ssh block.",
		"become_password_file": "IOS has no sudo, so there is no password to give it. Remove become_password_file from this ssh block.",
	} {
		v := conn.GetAttr(attr)
		if v.IsNull() || !v.IsKnown() || (v.Type() == cty.Bool && v.False()) {
			continue
		}
		diags = diags.Append(tfdiags.AttributeValue(tfdiags.Error, "Invalid ssh setting for a Cisco IOS device", why,
			cty.GetAttrPath("ssh").GetAttr(attr)))
	}
	if v := optional(conn, "confirm_after"); known(v) {
		if d, err := time.ParseDuration(v.AsString()); err == nil {
			if err := ios.CheckConfirmAfter(d); err != nil {
				diags = diags.Append(tfdiags.AttributeValue(tfdiags.Error, "Invalid ssh confirm_after", err.Error(),
					cty.GetAttrPath("ssh").GetAttr("confirm_after")))
			}
		}
	}
	return diags
}

func iosConfigFrom(v cty.Value) ios.Config {
	c := ios.Config{Lines: stringList(v.GetAttr("lines")), Match: stringOr(v.GetAttr("match"), ios.MatchLines)}
	if p := v.GetAttr("parents"); known(p) {
		c.Parents = stringList(p)
	}
	return c
}

var iosConfigKind = cliKind{
	p:        iosPlatform,
	name:     "config",
	keys:     []string{"parents"},
	settings: []string{"lines", "match"},
	config:   func(v cty.Value) cliWant { return iosConfigFrom(v) },
	remove:   func(v cty.Value, running string) []string { return iosConfigFrom(v).RemoveCommands(running) },
}

func iosConfigSchema() providers.Schema {
	return providers.Schema{Block: &configschema.Block{
		Description: iosExperimental + "Lines of a Cisco IOS XE device's running configuration, under parent blocks or at the top level. Only the lines named here are owned; with match = \"block\" the block must be exactly these.",
		Attributes: map[string]*configschema.Attribute{
			"id":        {Type: cty.String, Computed: true},
			"revision":  revisionAttr(),
			"parents":   {Type: cty.List(cty.String), Optional: true, Description: "The blocks the lines sit in, outermost first, as show running-config prints them, such as [\"interface GigabitEthernet1\"]. Unset is the top level."},
			"lines":     {Type: cty.List(cty.String), Optional: true, Description: "The lines, exactly as show running-config prints them without their indent, such as \"description uplink\". A line the device prints differently never shows as in sync."},
			"match":     {Type: cty.String, Optional: true, Description: "\"lines\" (default): these lines must be there, and others are left alone. \"block\": the block under parents must be exactly these lines, so others are removed. Needs parents."},
			"on_remove": {Type: cty.String, Optional: true, Computed: true, Description: "What happens on the device when this resource is removed: \"forget\" (default) leaves the lines, \"delete\" removes them with their \"no\" form."},
			"in_sync":   {Type: cty.Bool, Computed: true, Description: "Whether the device had these lines at the last refresh."},
			"circuit":   eosCircuitAttr(),
		},
		BlockTypes: map[string]*configschema.NestedBlock{"ssh": connectionBlock()},
	}}
}

func validateIOSConfig(cfg cty.Value) tfdiags.Diagnostics {
	var diags tfdiags.Diagnostics
	if cfg.IsNull() || !cfg.IsWhollyKnown() {
		return diags
	}
	diags = diags.Append(validateOnRemove(cfg))
	if err := iosConfigFrom(cfg).Validate(); err != nil {
		diags = diags.Append(attrError("lines", err.Error()))
	}
	return diags
}
