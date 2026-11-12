// Copyright (c) The Conn3x Authors
// SPDX-License-Identifier: MPL-2.0

package provider

import (
	"context"
	"fmt"
	"slices"
	"strconv"
	"strings"

	"github.com/zclconf/go-cty/cty"

	"github.com/opentofu/opentofu/internal/conn3x/convert/ansible"
	"github.com/opentofu/opentofu/internal/conn3x/importid"
	"github.com/opentofu/opentofu/internal/providers"
)

// import_id lets a root import block adopt a step inside a module, such as
// an official circuit, where a step's own import can't reach:
//
//	import {
//	  for_each = local.hosts
//	  to       = module.web.conn3x_file.nginx__conf[each.key]
//	  id       = provider::conn3x::import_id(each.key, { host = each.value, user = "root" }, { path = "/etc/nginx/nginx.conf" })
//	}
//
// inventory reads a group's hosts from an Ansible inventory, for a
// circuit's hosts:
//
//	hosts = provider::conn3x::inventory("${path.module}/inventory.ini", "webservers")
var functions = map[string]providers.FunctionSpec{
	"inventory": {
		Parameters: []providers.FunctionParameterSpec{
			{Name: "path", Type: cty.String, Description: "The inventory file, INI or YAML. A relative path is relative to where conn3x runs; start it with path.module to make it relative to the configuration."},
			{Name: "group", Type: cty.String, Description: "The group whose hosts to return, with its child groups' hosts, or \"all\"."},
		},
		Return:  cty.DynamicPseudoType,
		Summary: "A group's hosts from an Ansible inventory, as a circuit's hosts.",
		Description: "Each host's key is its inventory name. Its address is ansible_host, or the name. " +
			"ansible_port, ansible_user and ansible_ssh_private_key_file become port, user and private_key_file, where they're set. " +
			"vars holds every plain variable the host has, from the inventory file and the group_vars and host_vars directories beside it, resolved as Ansible resolves them.",
	},
	"import_id": {
		Parameters: []providers.FunctionParameterSpec{
			{Name: "key", Type: cty.String, Description: "The host's key in the circuit's hosts, such as web1."},
			{Name: "ssh", Type: cty.DynamicPseudoType, Description: "The circuit's ssh settings, with the host's address as host."},
			{Name: "args", Type: cty.DynamicPseudoType, Description: "The step's module arguments as the circuit sets them; content, content_wo and validate are left out."},
		},
		Return:  cty.String,
		Summary: "The import ID for one host of a step, as a step's import = true would write it.",
	},
}

func (p *Provider) GetFunctions(context.Context) providers.GetFunctionsResponse {
	return providers.GetFunctionsResponse{Functions: functions}
}

func (p *Provider) CallFunction(_ context.Context, req providers.CallFunctionRequest) providers.CallFunctionResponse {
	if req.Name == "inventory" {
		return inventory(req.Arguments)
	}
	if req.Name != "import_id" {
		return providers.CallFunctionResponse{Error: fmt.Errorf("the conn3x provider has no function %q", req.Name)}
	}
	if len(req.Arguments) != 3 {
		return providers.CallFunctionResponse{Error: fmt.Errorf("import_id takes 3 arguments, key, ssh and args, not %d", len(req.Arguments))}
	}
	key := req.Arguments[0]
	if key.IsNull() {
		return providers.CallFunctionResponse{Error: &providers.CallFunctionArgumentError{Text: "key can't be null", FunctionArgument: 0}}
	}
	id, err := importid.Build(key.AsString(), req.Arguments[1], req.Arguments[2])
	if err != nil {
		return providers.CallFunctionResponse{Error: fmt.Errorf("import_id: %w", err)}
	}
	return providers.CallFunctionResponse{Result: cty.StringVal(id)}
}

// sshVars are the inventory variables a host object carries as its own
// connection settings.
var sshVars = map[string]string{"ansible_port": "port", "ansible_user": "user", "ansible_ssh_private_key_file": "private_key_file"}

func inventory(args []cty.Value) providers.CallFunctionResponse {
	if len(args) != 2 {
		return providers.CallFunctionResponse{Error: fmt.Errorf("inventory takes 2 arguments, path and group, not %d", len(args))}
	}
	for i, a := range args {
		if a.IsNull() {
			return providers.CallFunctionResponse{Error: &providers.CallFunctionArgumentError{Text: "can't be null", FunctionArgument: i}}
		}
	}
	path, name := args[0].AsString(), args[1].AsString()
	inv, err := ansible.ReadInventory(path)
	if err != nil {
		return providers.CallFunctionResponse{Error: fmt.Errorf("inventory: %w", err)}
	}
	g := inv.Group(name)
	if g == nil {
		return providers.CallFunctionResponse{Error: &providers.CallFunctionArgumentError{
			Text:             fmt.Sprintf("%s has no group %q; it has %s", path, name, strings.Join(append(slices.DeleteFunc(inv.GroupNames(), func(n string) bool { return n == "all" }), "all"), ", ")),
			FunctionArgument: 1,
		}}
	}
	hosts := map[string]cty.Value{}
	for _, h := range g.Names() {
		vars := g.Vars(h)
		obj := map[string]cty.Value{"address": cty.StringVal(h)}
		if a := vars["ansible_host"]; a != "" && !ansible.Encrypted(a) {
			obj["address"] = cty.StringVal(a)
		}
		for from, to := range sshVars {
			v, ok := vars[from]
			if !ok || v == "" || ansible.Encrypted(v) {
				continue
			}
			obj[to] = cty.StringVal(v)
			if to == "port" {
				n, err := strconv.Atoi(v)
				if err != nil || n < 1 || n > 65535 {
					return providers.CallFunctionResponse{Error: fmt.Errorf("inventory: %s sets ansible_port for %s to %q, which isn't a port number", path, h, v)}
				}
				obj[to] = cty.NumberIntVal(int64(n))
			}
		}
		vm := map[string]cty.Value{}
		for k, v := range vars {
			if !ansible.Encrypted(v) {
				vm[k] = cty.StringVal(v)
			}
		}
		obj["vars"] = cty.MapValEmpty(cty.String)
		if len(vm) > 0 {
			obj["vars"] = cty.MapVal(vm)
		}
		hosts[h] = cty.ObjectVal(obj)
	}
	if len(hosts) == 0 {
		return providers.CallFunctionResponse{Result: cty.EmptyObjectVal}
	}
	return providers.CallFunctionResponse{Result: cty.ObjectVal(hosts)}
}
