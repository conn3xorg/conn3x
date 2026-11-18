// Copyright (c) The Conn3x Authors
// SPDX-License-Identifier: MPL-2.0

package provider

import (
	"context"
	"encoding/json"
	"fmt"
	"sort"
	"strconv"
	"strings"

	"github.com/zclconf/go-cty/cty"
	"github.com/zclconf/go-cty/cty/convert"

	"github.com/opentofu/opentofu/internal/conn3x/modules/pkg"
	"github.com/opentofu/opentofu/internal/conn3x/modules/schedule"
	"github.com/opentofu/opentofu/internal/conn3x/modules/service"
	"github.com/opentofu/opentofu/internal/conn3x/modules/windows"
)

// ListKind is one kind of object conn3x generate steps can list on a host:
// the module whose steps adopt it, the argument that names one, and, for a
// module whose step needs it, the argument its value goes in.
type ListKind struct {
	Module, Key, Value string
	// Full is for a kind whose step takes several arguments from the host:
	// each value is then JSON, {"attrs": {...}} with the step's arguments,
	// or {"skip": "why"} for one the step can't adopt as it is.
	Full bool
}

// ListKinds are the kinds a host can be listed for.
var ListKinds = map[string]ListKind{
	"packages": {"package", "name", "", false},
	// manual_packages is packages without those pulled in as dependencies
	// or shipped with the image, which are most of a fresh host's.
	"manual_packages": {"package", "name", "", false},
	"services":        {"service", "name", "", false},
	"users":           {"user", "name", "", false},
	"mounts":          {"mount", "path", "", false},
	"sysctl":          {"sysctl", "name", "value", false},
	"timers":          {"timer", "name", "", true},

	"windows_features": {"windows_feature", "name", "", false},
	"windows_services": {"windows_service", "name", "", false},
	"windows_users":    {"windows_user", "name", "", false},
	"windows_groups":   {"windows_group", "name", "", false},
}

// ListHost lists the objects of kind a host has, by the value of the
// argument that names each: package names, service units, login users with
// a UID from 1000 (the accounts people made, not the system's), the mount
// points /etc/fstab lists, and the kernel parameters set in /etc/sysctl.conf
// and /etc/sysctl.d. values holds each one's value for a kind with a Value
// argument.
func ListHost(ctx context.Context, kind string, conn cty.Value) (names []string, values map[string]string, err error) {
	h, err := dialConnection(ctx, fullSSH(conn))
	if err != nil {
		return nil, nil, err
	}
	switch kind {
	case "windows_features", "windows_services", "windows_users", "windows_groups":
		names, err = windows.Inventory(ctx, h.raw(), strings.TrimPrefix(kind, "windows_"))
		if err != nil {
			return nil, nil, err
		}
	case "packages", "manual_packages":
		family, err := h.packageFamily(ctx)
		if err != nil {
			return nil, nil, err
		}
		got, err := pkg.Inventory(ctx, h, family)
		if err != nil {
			return nil, nil, err
		}
		var manual map[string]bool
		if kind == "manual_packages" {
			if manual, err = pkg.Manual(ctx, h, family); err != nil {
				return nil, nil, err
			}
		}
		for n := range got {
			key := n
			if family == pkg.RPM {
				key = pkg.BareName(n) // dnf's list has no architectures
			}
			if manual == nil || manual[key] {
				names = append(names, n)
			}
		}
	case "services":
		got, err := service.Inventory(ctx, h)
		if err != nil {
			return nil, nil, err
		}
		for n := range got {
			names = append(names, n)
		}
	case "sysctl":
		// The files in the order sysctl --system reads them, so a later
		// file's setting wins, as it does on the host.
		res, err := h.Run(ctx, "cat /etc/sysctl.conf $(ls /etc/sysctl.d/*.conf 2>/dev/null | sort) 2>/dev/null; true", nil)
		if err != nil {
			return nil, nil, err
		}
		values = map[string]string{}
		for _, line := range strings.Split(string(res.Stdout), "\n") {
			line = strings.TrimSpace(line)
			key, value, ok := strings.Cut(line, "=")
			if !ok || line == "" || strings.HasPrefix(line, "#") || strings.HasPrefix(line, ";") {
				continue
			}
			// A leading - means "ignore errors", not part of the name.
			key = strings.TrimPrefix(strings.TrimSpace(key), "-")
			if _, seen := values[key]; !seen {
				names = append(names, key)
			}
			values[key] = strings.Join(strings.Fields(value), " ")
		}
	case "timers":
		// Only timers someone wrote into /etc/systemd/system, not links to
		// a package's own under /usr/lib.
		res, err := h.Run(ctx, `for t in /etc/systemd/system/*.timer; do
  [ -f "$t" ] && [ ! -L "$t" ] || continue
  n=$(basename "$t" .timer)
  printf '\036%s\037' "$n"; cat "$t"; printf '\037'; cat "/etc/systemd/system/$n.service" 2>/dev/null
  printf '\037'
  for d in /etc/systemd/system /run/systemd/system; do
    for u in "$n.timer" "$n.service"; do
      ls "$d/$u.d/"*.conf >/dev/null 2>&1 && printf '%s ' "$d/$u.d"
    done
  done
done; true`, nil)
		if err != nil {
			return nil, nil, err
		}
		values = map[string]string{}
		for _, rec := range strings.Split(string(res.Stdout), "\x1e")[1:] {
			parts := strings.SplitN(rec, "\x1f", 4)
			if len(parts) != 4 {
				continue
			}
			names = append(names, parts[0])
			values[parts[0]] = timerJSON(parts[0], parts[2], parts[1], strings.Fields(parts[3]))
		}
	case "users", "mounts":
		cmd := "getent passwd"
		if kind == "mounts" {
			cmd = "cat /etc/fstab"
		}
		res, err := h.Run(ctx, cmd, nil)
		if err != nil {
			return nil, nil, err
		}
		if res.ExitCode != 0 {
			return nil, nil, fmt.Errorf("%s: %s", cmd, strings.TrimSpace(string(res.Stderr)))
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
		return nil, nil, fmt.Errorf("can't list %q; conn3x generate steps lists packages, services, users, mounts, sysctl and timers, and on Windows windows_features, windows_services, windows_users and windows_groups", kind)
	}
	sort.Strings(names)
	return names, values, nil
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

// timerJSON is a timer's step arguments, or why it can't be adopted, as
// ListKind.Full describes.
// dropIns are the timer's and its service's drop-in directories: systemd
// applies them over the units, so what the units say isn't what runs.
func timerJSON(name, service, timer string, dropIns []string) string {
	t, why := schedule.ParseTimer(name, service, timer)
	if why == "" && len(dropIns) > 0 {
		why = "drop-ins in " + strings.Join(dropIns, " and ") + " change what the units say, and a timer step reads only the units; fold them in first"
	}
	if why != "" {
		b, _ := json.Marshal(map[string]string{"skip": why})
		return string(b)
	}
	attrs := map[string]any{"name": t.Name, "on_calendar": t.OnCalendar, "command": t.Command}
	if t.User != "" {
		attrs["user"] = t.User
	}
	if t.Description != "" {
		attrs["description"] = t.Description
	}
	if t.Persistent {
		attrs["persistent"] = true
	}
	b, _ := json.Marshal(map[string]any{"attrs": attrs})
	return string(b)
}
