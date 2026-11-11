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
// line with only "--", then systemctl show's properties for them, a block
// each. Names are passed one per line as they are: systemd escapes
// instance names with backslashes, such as dev-disk-by\x2duuid, which
// xargs would otherwise read as escapes.
const inventoryScript = `names=$({
  systemctl list-unit-files --type=service --no-legend --no-pager --plain
  systemctl list-units --all --type=service --no-legend --no-pager --plain
} | awk '{ u = $1; if (u == "●") u = $2; if (u ~ /\.service$/ && u !~ /@\.service$/) print u }' | LC_ALL=C sort -u) || exit 1
printf '%s\n--\n' "$names"
[ -z "$names" ] || printf '%s\n' "$names" | xargs -d '\n' systemctl show -p Id,Names,LoadState,ActiveState,UnitFileState --`

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
	// Each block is found by the names it answers to: its Id, and every
	// alias in Names, such as sshd for ssh on Debian. Not by position,
	// which only holds while each name gets exactly one block.
	byName := map[string]map[string]string{}
	for _, b := range strings.Split(strings.TrimSpace(body), "\n\n") {
		props := map[string]string{}
		for _, l := range strings.Split(b, "\n") {
			if k, v, ok := strings.Cut(l, "="); ok {
				props[k] = v
			}
		}
		for _, n := range append(strings.Fields(props["Names"]), props["Id"]) {
			byName[n] = props
		}
	}
	got := map[string]UnitState{}
	for _, n := range names {
		p, ok := byName[n]
		if !ok {
			return nil, fmt.Errorf("listing services: systemctl show said nothing about %s", n)
		}
		// A unit something refers to but nothing provides isn't a service.
		if p["LoadState"] == "not-found" {
			continue
		}
		got[strings.TrimSuffix(n, ".service")] = UnitState{State: p["ActiveState"], UnitFileState: p["UnitFileState"]}
	}
	return got, nil
}
