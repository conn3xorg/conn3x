// Copyright (c) The Conn3x Authors
// SPDX-License-Identifier: MPL-2.0

package provider

import (
	"crypto/rand"
	"encoding/hex"

	"github.com/zclconf/go-cty/cty"

	"github.com/opentofu/opentofu/internal/configs/configschema"
)

// Every host resource has a revision that changes exactly when Conn3x
// changes something on the host. Handlers watch it, so putting back a hand
// edit fires them too, even though the result matches the last apply.

func revisionAttr() *configschema.Attribute {
	return &configschema.Attribute{
		Type: cty.String, Computed: true,
		Description: "Changes each time Conn3x changes this on the host. Handlers watch it.",
	}
}

// planRevision keeps the prior revision when the plan changes nothing on
// the host, and leaves it unknown when the host is about to change.
func planRevision(prior, planned cty.Value) cty.Value {
	if planned.IsNull() || !planned.Type().IsObjectType() || !planned.Type().HasAttribute("revision") {
		return planned
	}
	vals := planned.AsValueMap()
	if prior.IsNull() {
		vals["revision"] = cty.UnknownVal(cty.String)
		return cty.ObjectVal(vals)
	}
	vals["revision"] = prior.GetAttr("revision")
	if same := cty.ObjectVal(vals); hostSettings(same, prior).RawEquals(prior) {
		return same
	}
	vals["revision"] = cty.UnknownVal(cty.String)
	return cty.ObjectVal(vals)
}

// offHost are settings that change nothing on the host when they change:
// what to do on removal, and how long to wait for a reboot or a wait_for.
var offHost = []string{"on_remove", "timeout"}

// sshMachine are the ssh settings that choose which machine is reached.
// The rest only change how Conn3x logs in to it.
var sshMachine = []string{"host", "port", "ssh_config_file"}

// hostSettings is planned with every setting that doesn't touch the host
// taken from prior, so comparing it with prior compares only what does.
func hostSettings(planned, prior cty.Value) cty.Value {
	vals := planned.AsValueMap()
	for _, name := range offHost {
		if _, ok := vals[name]; ok {
			vals[name] = prior.GetAttr(name)
		}
	}
	if ssh, ok := vals["ssh"]; ok {
		was := prior.GetAttr("ssh")
		if ssh.IsNull() || !ssh.IsKnown() || was.IsNull() || !was.IsKnown() {
			return cty.ObjectVal(vals)
		}
		conn := was.AsValueMap()
		for _, name := range sshMachine {
			if _, ok := conn[name]; ok {
				conn[name] = ssh.GetAttr(name)
			}
		}
		vals["ssh"] = cty.ObjectVal(conn)
	}
	return cty.ObjectVal(vals)
}

// applyRevision gives an applied change a new revision.
func applyRevision(planned, state cty.Value) cty.Value {
	if state.IsNull() || !state.Type().HasAttribute("revision") || planned.IsNull() || planned.GetAttr("revision").IsKnown() {
		return state
	}
	b := make([]byte, 8)
	_, _ = rand.Read(b)
	vals := state.AsValueMap()
	vals["revision"] = cty.StringVal(hex.EncodeToString(b))
	return cty.ObjectVal(vals)
}
