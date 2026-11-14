// Copyright (c) The Conn3x Authors
// SPDX-License-Identifier: MPL-2.0

package provider

import (
	"context"
	"fmt"

	"github.com/zclconf/go-cty/cty"

	"github.com/opentofu/opentofu/internal/configs/configschema"
	"github.com/opentofu/opentofu/internal/conn3x/modules/sshkey"
	"github.com/opentofu/opentofu/internal/providers"
)

func sshKeypairSchema() providers.Schema {
	return providers.Schema{Block: &configschema.Block{
		Description: "An SSH key made on the host with its ssh-keygen, so the private key never leaves it. Only the public key is in state.",
		Attributes: map[string]*configschema.Attribute{
			"id":         {Type: cty.String, Computed: true},
			"revision":   revisionAttr(),
			"path":       {Type: cty.String, Required: true, Description: "Absolute path of the private key, such as /home/deploy/.ssh/id_ed25519. The public key goes beside it, with .pub on the end."},
			"type":       {Type: cty.String, Optional: true, Description: "\"ed25519\" (default), \"rsa\" or \"ecdsa\". Changing it, or bits, makes a new key."},
			"bits":       {Type: cty.Number, Optional: true, Description: "For rsa: 3072 (default) or 4096. For ecdsa: 256 (default), 384 or 521."},
			"comment":    {Type: cty.String, Optional: true, Description: "The comment at the end of the public key, such as deploy@web1."},
			"owner":      {Type: cty.String, Optional: true, Description: "Owner of both files. Unset keeps the key's."},
			"group":      {Type: cty.String, Optional: true, Description: "Group of both files. Unset keeps the key's."},
			"on_remove":  {Type: cty.String, Optional: true, Computed: true, Description: "\"forget\" (default) leaves the key, \"delete\" removes both files."},
			"public_key": {Type: cty.String, Computed: true, Description: "The public key, as a line for authorized_keys or a git host's deploy keys."},
			"in_sync":    {Type: cty.Bool, Computed: true, Description: "Whether the host has a key of this kind, mode 0600, with this owner and group, and the .pub file to match."},
		},
		BlockTypes: map[string]*configschema.NestedBlock{"ssh": connectionBlock()},
	}}
}

func sshKeypairFrom(v cty.Value) sshkey.Keypair {
	return sshkey.Keypair{Path: stringOr(v.GetAttr("path"), ""), Type: stringOr(v.GetAttr("type"), ""), Bits: intOr(v.GetAttr("bits"), 0),
		Comment: stringOr(v.GetAttr("comment"), ""), Owner: stringOr(v.GetAttr("owner"), ""), Group: stringOr(v.GetAttr("group"), "")}
}

func planSSHKeypair(req providers.PlanResourceChangeRequest) providers.PlanResourceChangeResponse {
	return unknownWhenStale(planSynced(req, "ssh_keypair", []string{"path"}, []string{"type", "bits", "comment", "owner", "group"}), "public_key")
}

func readSSHKeypair(ctx context.Context, req providers.ReadResourceRequest) providers.ReadResourceResponse {
	return readPathResource(ctx, req, func(ctx context.Context, h *hostConn, prior cty.Value) (cty.Value, error) {
		k := sshKeypairFrom(prior)
		s, err := sshkey.ReadKeypair(ctx, h, k.Path)
		if err != nil {
			return cty.NilVal, err
		}
		return withSync(withAttr(prior, "public_key", k.PublicKey(s)), k.Matches(s)), nil
	})
}

func applySSHKeypair(ctx context.Context, req providers.ApplyResourceChangeRequest) providers.ApplyResourceChangeResponse {
	return applyPathResource(ctx, req,
		func(ctx context.Context, h *hostConn, planned cty.Value) (cty.Value, error) {
			k := sshKeypairFrom(planned)
			s, err := sshkey.ApplyKeypair(ctx, h, k)
			if err != nil {
				return cty.NilVal, fmt.Errorf("ssh_keypair %s: %w", k.Path, err)
			}
			return withSync(withAttr(planned, "public_key", k.PublicKey(s)), true), nil
		},
		func(ctx context.Context, h *hostConn, prior cty.Value) error {
			return sshkey.DeleteKeypair(ctx, h, prior.GetAttr("path").AsString())
		})
}
