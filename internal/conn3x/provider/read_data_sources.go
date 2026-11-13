// Copyright (c) The Conn3x Authors
// SPDX-License-Identifier: MPL-2.0

package provider

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"path"

	"github.com/zclconf/go-cty/cty"

	"github.com/opentofu/opentofu/internal/configs/configschema"
	"github.com/opentofu/opentofu/internal/conn3x/modules/file"
	"github.com/opentofu/opentofu/internal/providers"
	"github.com/opentofu/opentofu/internal/tfdiags"
)

// defaultMaxRead is how much of a file conn3x_file reads unless told more:
// a data source's value lands in state, so it's meant for tokens and
// version files, not for logs.
const defaultMaxRead = 1 << 20

// fileDataSchema is conn3x_file: a file on the host, read at every plan.
func fileDataSchema() providers.Schema {
	return providers.Schema{Block: &configschema.Block{
		Description: "Reads a file on the host at every plan, such as a token another step wrote or a version file, for a later step or a check block. Read-only. The content lands in state, marked sensitive.",
		Attributes: map[string]*configschema.Attribute{
			"id":       {Type: cty.String, Computed: true},
			"path":     {Type: cty.String, Required: true, Description: "The file, absolute."},
			"max_size": {Type: cty.Number, Optional: true, Description: "The largest file to read, in bytes; 1048576 (1 MiB) unless set. A bigger file is an error."},
			"exists":   {Type: cty.Bool, Computed: true, Description: "Whether the file is there. The rest is null when it isn't."},
			"content":  {Type: cty.String, Computed: true, Sensitive: true, Description: "The file's content."},
			"size":     {Type: cty.Number, Computed: true, Description: "Its size in bytes."},
			"sha256":   {Type: cty.String, Computed: true, Description: "The SHA-256 of its content, hex."},
			"mode":     {Type: cty.String, Computed: true, Description: "Its mode, four octal digits, such as 0644."},
			"owner":    {Type: cty.String, Computed: true, Description: "Its owner."},
			"group":    {Type: cty.String, Computed: true, Description: "Its group."},
		},
		BlockTypes: map[string]*configschema.NestedBlock{"ssh": connectionBlock()},
	}}
}

func validateFileData(cfg cty.Value) tfdiags.Diagnostics {
	var diags tfdiags.Diagnostics
	if p := cfg.GetAttr("path"); known(p) && !path.IsAbs(p.AsString()) {
		diags = diags.Append(attrError("path", fmt.Sprintf("path %q must be absolute", p.AsString())))
	}
	if m := cfg.GetAttr("max_size"); known(m) {
		if n, _ := m.AsBigFloat().Int64(); n < 1 {
			diags = diags.Append(attrError("max_size", "max_size must be at least 1"))
		}
	}
	return diags
}

func readFileData(ctx context.Context, req providers.ReadDataSourceRequest) providers.ReadDataSourceResponse {
	var resp providers.ReadDataSourceResponse
	conn := req.Config.GetAttr("ssh")
	h, err := dialConnection(ctx, conn)
	if err != nil {
		resp.Diagnostics = resp.Diagnostics.Append(attrError("ssh", err.Error()))
		return resp
	}
	p := req.Config.GetAttr("path").AsString()
	limit := int64(defaultMaxRead)
	if m := req.Config.GetAttr("max_size"); known(m) {
		limit, _ = m.AsBigFloat().Int64()
	}
	a, err := file.Read(ctx, h, p)
	if err != nil {
		resp.Diagnostics = resp.Diagnostics.Append(fmt.Errorf("conn3x_file: %w", err))
		return resp
	}
	vals := req.Config.AsValueMap()
	vals["id"] = cty.StringVal(hostPort(conn) + ":" + p)
	vals["exists"] = cty.BoolVal(a.Exists)
	for _, k := range []string{"content", "sha256", "mode", "owner", "group"} {
		vals[k] = cty.NullVal(cty.String)
	}
	vals["size"] = cty.NullVal(cty.Number)
	if a.Exists {
		if int64(len(a.Content)) > limit {
			resp.Diagnostics = resp.Diagnostics.Append(fmt.Errorf("conn3x_file: %s is %d bytes, over max_size (%d); raise max_size if you mean to keep that much in state", p, len(a.Content), limit))
			return resp
		}
		sum := sha256.Sum256([]byte(a.Content))
		vals["content"] = cty.StringVal(a.Content)
		vals["sha256"] = cty.StringVal(hex.EncodeToString(sum[:]))
		vals["size"] = cty.NumberIntVal(int64(len(a.Content)))
		vals["mode"], vals["owner"], vals["group"] = cty.StringVal(a.Mode), cty.StringVal(a.Owner), cty.StringVal(a.Group)
	}
	resp.State = cty.ObjectVal(vals)
	return resp
}

// commandDataSchema is conn3x_command: a command's output, at every plan.
func commandDataSchema() providers.Schema {
	return providers.Schema{Block: &configschema.Block{
		Description: "Runs a command on the host at every plan and returns what it printed, such as kubeadm token create --print-join-command for a step on the other hosts, or a compliance check for a check block. It must not change anything: plans run it, and so does every refresh. Its output lands in state, marked sensitive.",
		Attributes: map[string]*configschema.Attribute{
			"id":        {Type: cty.String, Computed: true},
			"command":   {Type: cty.String, Required: true, Description: "The command, run with /bin/sh in the C locale, as root through become when the ssh block says so."},
			"stdout":    {Type: cty.String, Computed: true, Sensitive: true, Description: "What it printed on stdout."},
			"stderr":    {Type: cty.String, Computed: true, Sensitive: true, Description: "What it printed on stderr."},
			"exit_code": {Type: cty.Number, Computed: true, Description: "Its exit status. A non-zero one isn't an error: check it in a postcondition or a check block."},
		},
		BlockTypes: map[string]*configschema.NestedBlock{"ssh": connectionBlock()},
	}}
}

func validateCommandData(cfg cty.Value) tfdiags.Diagnostics {
	var diags tfdiags.Diagnostics
	if c := cfg.GetAttr("command"); known(c) && c.AsString() == "" {
		diags = diags.Append(attrError("command", "command must not be empty"))
	}
	return diags
}

func readCommandData(ctx context.Context, req providers.ReadDataSourceRequest) providers.ReadDataSourceResponse {
	var resp providers.ReadDataSourceResponse
	conn := req.Config.GetAttr("ssh")
	h, err := dialConnection(ctx, conn)
	if err != nil {
		resp.Diagnostics = resp.Diagnostics.Append(attrError("ssh", err.Error()))
		return resp
	}
	cmd := req.Config.GetAttr("command").AsString()
	res, err := h.Run(ctx, cmd, nil)
	if err != nil {
		resp.Diagnostics = resp.Diagnostics.Append(fmt.Errorf("conn3x_command: %w", err))
		return resp
	}
	vals := req.Config.AsValueMap()
	sum := sha256.Sum256([]byte(cmd))
	vals["id"] = cty.StringVal(hostPort(conn) + ":" + hex.EncodeToString(sum[:8]))
	vals["stdout"], vals["stderr"] = cty.StringVal(string(res.Stdout)), cty.StringVal(string(res.Stderr))
	vals["exit_code"] = cty.NumberIntVal(int64(res.ExitCode))
	resp.State = cty.ObjectVal(vals)
	return resp
}
