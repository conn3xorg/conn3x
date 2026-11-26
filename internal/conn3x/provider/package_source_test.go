// Copyright (c) The Conn3x Authors
// SPDX-License-Identifier: MPL-2.0

package provider

import (
	"strings"
	"testing"

	"github.com/zclconf/go-cty/cty"
)

func sourcePrior(t *testing.T, installed, file cty.Value) cty.Value {
	return packageObj(t, map[string]cty.Value{
		"id": cty.StringVal("203.0.113.10:package:agent"), "name": cty.StringVal("agent"), "state": cty.StringVal("present"),
		"on_remove": cty.StringVal("forget"), "source": cty.StringVal("/opt/dl/agent.deb"),
		"installed_version": installed, "source_version": file,
	})
}

// A package step with source is in sync when what's installed is the
// file's version, plans an install when the file on the host is another
// one, and never promises a version an apply has to read (#1350).
func TestPackageSourcePlan(t *testing.T) {
	cfg := packageObj(t, map[string]cty.Value{"name": cty.StringVal("agent"), "source": cty.StringVal("/opt/dl/agent.deb")})
	v14, v15, null := cty.StringVal("1.4.0-1"), cty.StringVal("1.5.0-1"), cty.NullVal(cty.String)

	// Before the file exists, as when a download step comes first.
	if p := planPkg(t, cty.NullVal(cfg.Type()), cfg); p.GetAttr("installed_version").IsKnown() || p.GetAttr("source_version").IsKnown() {
		t.Fatalf("create: %#v", p)
	}
	for name, tc := range map[string]struct {
		prior cty.Value
		clean bool
	}{
		"in sync":              {sourcePrior(t, v14, v14), true},
		"newer file":           {sourcePrior(t, v14, v15), false},
		"older file":           {sourcePrior(t, v15, v14), false},
		"file gone, installed": {sourcePrior(t, v14, null), true},
		"not installed":        {sourcePrior(t, null, null), false},
	} {
		p := planPkg(t, tc.prior, cfg)
		if clean := p.RawEquals(tc.prior); clean != tc.clean {
			t.Errorf("%s: clean = %v: %#v", name, clean, p)
		}
		if !tc.clean && (p.GetAttr("installed_version").IsKnown() || p.GetAttr("source_version").IsKnown()) {
			t.Errorf("%s: planned known versions: %#v", name, p)
		}
	}

	// Any other change applies, and the apply reads the file again: an
	// earlier step may replace it, so nothing read can be planned (#1376).
	onRemove := packageObj(t, map[string]cty.Value{"name": cty.StringVal("agent"), "source": cty.StringVal("/opt/dl/agent.deb"), "on_remove": cty.StringVal("delete")})
	if p := planPkg(t, sourcePrior(t, v14, v14), onRemove); p.GetAttr("installed_version").IsKnown() || p.GetAttr("source_version").IsKnown() {
		t.Fatalf("on_remove change planned known versions: %#v", p)
	}
	// So does another path, whose file the refresh didn't read.
	moved := packageObj(t, map[string]cty.Value{"name": cty.StringVal("agent"), "source": cty.StringVal("/opt/dl/agent-1.4.0.deb")})
	if p := planPkg(t, sourcePrior(t, v14, v14), moved); p.GetAttr("source_version").IsKnown() {
		t.Fatalf("new path planned a known source_version: %#v", p)
	}
	// Without source, or to remove it, there's no file to read.
	plain := packageObj(t, map[string]cty.Value{"name": cty.StringVal("agent")})
	if p := planPkg(t, sourcePrior(t, v14, v14), plain); !p.GetAttr("source_version").IsNull() {
		t.Fatalf("dropping source: %#v", p)
	}
	absent := packageObj(t, map[string]cty.Value{"name": cty.StringVal("agent"), "source": cty.StringVal("/opt/dl/agent.deb"), "state": cty.StringVal("absent")})
	if p := planPkg(t, sourcePrior(t, v14, v14), absent); !p.GetAttr("source_version").IsNull() || p.GetAttr("installed_version").IsKnown() {
		t.Fatalf("absent: %#v", p)
	}
}

func TestPackageSourceValidate(t *testing.T) {
	for want, attrs := range map[string]map[string]cty.Value{
		"must be an absolute path":    {"source": cty.StringVal("agent.deb")},
		"must be an absolute path ":   {"source": cty.StringVal("/tmp/agent;reboot.deb")},
		"version can't be set":        {"source": cty.StringVal("/tmp/agent.deb"), "version": cty.StringVal("1.4.0")},
		"version can't be set ":       {"source": cty.UnknownVal(cty.String), "version": cty.StringVal("1.4.0")},
		`state "latest" can't be set`: {"source": cty.StringVal("/tmp/agent.rpm"), "state": cty.StringVal("latest")},
	} {
		attrs["name"] = cty.StringVal("agent")
		diags := validatePackage(packageObj(t, attrs))
		if !diags.HasErrors() || !strings.Contains(diags.Err().Error(), strings.TrimSpace(want)) {
			t.Errorf("%v: %v, want %q", attrs, diags.Err(), want)
		}
	}
	for _, src := range []cty.Value{cty.StringVal("/opt/dl/agent_1.4.0-1_amd64.deb"), cty.UnknownVal(cty.String)} {
		if diags := validatePackage(packageObj(t, map[string]cty.Value{"name": cty.StringVal("agent"), "source": src})); diags.HasErrors() {
			t.Errorf("%#v refused: %v", src, diags.Err())
		}
	}
}
