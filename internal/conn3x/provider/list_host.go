// Copyright (c) The Conn3x Authors
// SPDX-License-Identifier: MPL-2.0

package provider

import (
	"context"
	"fmt"
	"sort"
	"strconv"
	"strings"

	"github.com/zclconf/go-cty/cty"
	"github.com/zclconf/go-cty/cty/convert"

	"github.com/opentofu/opentofu/internal/conn3x/modules/pkg"
	"github.com/opentofu/opentofu/internal/conn3x/modules/service"
)

// ListKind is one kind of object conn3x generate steps can list on a host:
// the module whose steps adopt it, and the argument that names one.
type ListKind struct {
	Module, Key string
}

// ListKinds are the kinds a host can be listed for.
var ListKinds = map[string]ListKind{
	"packages": {"package", "name"},
	"services": {"service", "name"},
	"users":    {"user", "name"},
	"mounts":   {"mount", "path"},
}

// ListHost lists the objects of kind a host has, by the value of the
// argument that names each: package names, service units, login users with
// a UID from 1000 (the accounts people made, not the system's), and the
// mount points /etc/fstab lists.
func ListHost(ctx context.Context, kind string, conn cty.Value) ([]string, error) {
	h, err := dialConnection(ctx, fullSSH(conn))
	if err != nil {
		return nil, err
	}
	var names []string
	switch kind {
	case "packages":
		family, err := pkg.DetectFamily(ctx, h)
		if err != nil {
			return nil, err
		}
		got, err := pkg.Inventory(ctx, h, family)
		if err != nil {
			return nil, err
		}
		for n := range got {
			names = append(names, n)
		}
	case "services":
		got, err := service.Inventory(ctx, h)
		if err != nil {
			return nil, err
		}
		for n := range got {
			names = append(names, n)
		}
	case "users", "mounts":
		cmd := "getent passwd"
		if kind == "mounts" {
			cmd = "cat /etc/fstab"
		}
		res, err := h.Run(ctx, cmd, nil)
		if err != nil {
			return nil, err
		}
		if res.ExitCode != 0 {
			return nil, fmt.Errorf("%s: %s", cmd, strings.TrimSpace(string(res.Stderr)))
		}
		for _, line := range strings.Split(string(res.Stdout), "\n") {
			if kind == "users" {
				f := strings.Split(line, ":")
				if len(f) < 7 {
					continue
				}
				if uid, err := strconv.Atoi(f[2]); err == nil && uid >= 1000 && uid < 65534 {
					names = append(names, f[0])
				}
				continue
			}
			f := strings.Fields(line)
			if len(f) >= 3 && !strings.HasPrefix(f[0], "#") && strings.HasPrefix(f[1], "/") && f[2] != "swap" {
				names = append(names, f[1])
			}
		}
	default:
		return nil, fmt.Errorf("can't list %q; conn3x generate steps lists packages, services, users and mounts", kind)
	}
	sort.Strings(names)
	return names, nil
}

// fullSSH is conn with every attribute of an ssh block, null where conn
// doesn't set it, as dialConnection reads them.
func fullSSH(conn cty.Value) cty.Value {
	vals := map[string]cty.Value{}
	for name, ty := range connectionBlock().Block.ImpliedType().AttributeTypes() {
		vals[name] = cty.NullVal(ty)
		if conn.Type().HasAttribute(name) {
			if v, err := convert.Convert(conn.GetAttr(name), ty); err == nil {
				vals[name] = v
			}
		}
	}
	return cty.ObjectVal(vals)
}
