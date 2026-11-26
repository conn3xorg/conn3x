// Copyright (c) The Conn3x Authors
// SPDX-License-Identifier: MPL-2.0

package main

import (
	"fmt"
	"path"
	"slices"
	"strconv"
	"strings"

	"github.com/zclconf/go-cty/cty"
)

// factsModule is -m facts, which reads what a conn3x_host data source
// reads, as ansible -m setup does, and changes nothing.
const factsModule = "facts"

// factNames are the facts -m facts prints, in this order. A Windows host
// adds its windows object's, as windows_<name>.
var factNames = []string{"os_family", "os_id", "os_version", "os_codename", "service_manager", "arch", "cpus", "memory_mb", "ipv4"}

type fact struct {
	name string
	val  any // string, int64 or bool
}

// factFilter is -a 'filter=GLOB,GLOB' for -m facts: nil keeps every fact.
func factFilter(raw string) ([]string, error) {
	if raw == "" {
		return nil, nil
	}
	params, err := taskParams(raw)
	if err != nil {
		return nil, err
	}
	var globs []string
	for k, v := range params {
		if k != "filter" {
			return nil, fmt.Errorf("-m facts takes only filter, such as -a 'filter=os_*', not %s", k)
		}
		for _, g := range strings.Split(v.AsString(), ",") {
			if g = strings.TrimSpace(g); g != "" {
				if _, err := path.Match(g, ""); err != nil {
					return nil, fmt.Errorf("filter %q isn't a glob: %w", g, err)
				}
				globs = append(globs, g)
			}
		}
	}
	return globs, nil
}

// hostFacts is the facts in a conn3x_host state that filter keeps.
func hostFacts(state cty.Value, filter []string) []fact {
	var out []fact
	add := func(name string, v cty.Value) {
		if v.IsNull() || !v.IsKnown() {
			return
		}
		if filter != nil && !slices.ContainsFunc(filter, func(g string) bool { ok, _ := path.Match(g, name); return ok }) {
			return
		}
		switch v.Type() {
		case cty.Number:
			i, _ := v.AsBigFloat().Int64()
			out = append(out, fact{name, i})
		case cty.Bool:
			out = append(out, fact{name, v.True()})
		default:
			out = append(out, fact{name, v.AsString()})
		}
	}
	for _, n := range factNames {
		add(n, state.GetAttr(n))
	}
	if w := state.GetAttr("windows"); !w.IsNull() {
		names := slices.Sorted(func(yield func(string) bool) {
			for k := range w.Type().AttributeTypes() {
				if !yield(k) {
					return
				}
			}
		})
		for _, k := range names {
			add("windows_"+k, w.GetAttr(k))
		}
	}
	return out
}

// factLine is a host's facts on one line, as name=value pairs; a value
// with a space, a quote or an = in it, or none at all, is quoted.
func factLine(facts []fact) string {
	var b strings.Builder
	for i, f := range facts {
		if i > 0 {
			b.WriteByte(' ')
		}
		v := fmt.Sprint(f.val)
		if v == "" || strings.ContainsAny(v, " \t\"'=") {
			v = strconv.Quote(v)
		}
		b.WriteString(f.name + "=" + v)
	}
	return b.String()
}

func factMap(facts []fact) map[string]any {
	m := map[string]any{}
	for _, f := range facts {
		m[f.name] = f.val
	}
	return m
}
