// Copyright (c) The Conn3x Authors
// SPDX-License-Identifier: MPL-2.0

package service

import (
	"context"
	"fmt"
	"strings"

	"github.com/opentofu/opentofu/internal/conn3x/modules"
)

// UnitState is one service as systemd reports it.
type UnitState struct {
	// State is systemd's ActiveState: active, inactive, failed and so on.
	State string
	// UnitFileState is systemd's own word: enabled, disabled, static,
	// masked, indirect, generated and so on.
	UnitFileState string
}

// Enabled reports whether the service starts at boot by its own unit file.
// static, indirect, generated and masked all read false; masked above all.
func (u UnitState) Enabled() bool {
	return u.UnitFileState == "enabled" || u.UnitFileState == "enabled-runtime"
}

// inventoryScript prints every service unit's name, from the unit files
// (templates left out) and from what's loaded (their instances), then a
// line with only "--", then systemctl show's properties for each name in
// the same order, each block ending in a blank line.
const inventoryScript = `names=$({
  systemctl list-unit-files --type=service --no-legend --no-pager --plain
  systemctl list-units --all --type=service --no-legend --no-pager --plain
} | awk '{ u = $1; if (u == "●") u = $2; if (u ~ /\.service$/ && u !~ /@\.service$/) print u }' | LC_ALL=C sort -u) || exit 1
printf '%s\n--\n' "$names"
[ -z "$names" ] || printf '%s\n' "$names" | xargs systemctl show -p Id,LoadState,ActiveState,UnitFileState --`

// Inventory returns every service on the host by name, without ".service",
// as a service step takes it.
func Inventory(ctx context.Context, r modules.Runner) (map[string]UnitState, error) {
	res, err := systemctl(ctx, r, inventoryScript)
	if err != nil {
		return nil, err
	}
	if res.ExitCode != 0 {
		return nil, fmt.Errorf("listing services: %s", strings.TrimSpace(string(res.Stderr)))
	}
	return parseInventory(string(res.Stdout))
}

func parseInventory(out string) (map[string]UnitState, error) {
	head, body, ok := strings.Cut(out, "\n--\n")
	if !ok {
		return nil, fmt.Errorf("listing services: unexpected output %q", out)
	}
	var names []string
	for _, n := range strings.Split(head, "\n") {
		if n != "" {
			names = append(names, n)
		}
	}
	var blocks []map[string]string
	for _, b := range strings.Split(strings.TrimSpace(body), "\n\n") {
		if strings.TrimSpace(b) == "" {
			continue
		}
		props := map[string]string{}
		for _, l := range strings.Split(b, "\n") {
			if k, v, ok := strings.Cut(l, "="); ok {
				props[k] = v
			}
		}
		blocks = append(blocks, props)
	}
	if len(blocks) != len(names) {
		return nil, fmt.Errorf("listing services: %d names but %d answers from systemctl show", len(names), len(blocks))
	}
	got := map[string]UnitState{}
	for i, n := range names {
		p := blocks[i]
		// A unit something refers to but nothing provides isn't a service.
		if p["LoadState"] == "not-found" {
			continue
		}
		got[strings.TrimSuffix(n, ".service")] = UnitState{State: p["ActiveState"], UnitFileState: p["UnitFileState"]}
	}
	return got, nil
}
