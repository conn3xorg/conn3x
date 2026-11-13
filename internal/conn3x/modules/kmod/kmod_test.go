// Copyright (c) The Conn3x Authors
// SPDX-License-Identifier: MPL-2.0

package kmod

import "testing"

func TestValidate(t *testing.T) {
	if err := (Module{Name: "br_netfilter"}).Validate(); err != nil {
		t.Fatal(err)
	}
	if err := (Module{Name: "dummy", Params: []string{"numdummies=2"}}).Validate(); err != nil {
		t.Fatal(err)
	}
	for _, m := range []Module{
		{Name: "br netfilter"},
		{Name: "../x"},
		{Name: "dummy", Params: []string{"numdummies"}},
		{Name: "dummy", Params: []string{"n=1; reboot"}},
		{Name: "dummy", Params: []string{"n=1", "n=2"}},
		{Name: "dummy", Params: []string{"n=1"}, Absent: true},
	} {
		if m.Validate() == nil {
			t.Errorf("%+v should be refused", m)
		}
	}
}

func TestInSync(t *testing.T) {
	m := Module{Name: "nf-conntrack", Params: []string{"hashsize=65536", "acct=1"}, Persistent: true}
	if m.kernelName() != "nf_conntrack" || m.LoadPath() != "/etc/modules-load.d/nf-conntrack.conf" || m.OptionsPath() != "/etc/modprobe.d/nf-conntrack.conf" {
		t.Fatalf("names: %s %s %s", m.kernelName(), m.LoadPath(), m.OptionsPath())
	}
	good := Actual{Loaded: true, Params: map[string]string{"hashsize": "65536", "acct": "Y"}, LoadFile: m.loadContent(), OptionsFile: m.optionsContent()}
	if !m.InSync(good) {
		t.Error("a bool param shown as Y matches 1")
	}
	for name, a := range map[string]Actual{
		"not loaded":     {Params: good.Params, LoadFile: good.LoadFile, OptionsFile: good.OptionsFile},
		"other param":    {Loaded: true, Params: map[string]string{"hashsize": "1024", "acct": "Y"}, LoadFile: good.LoadFile, OptionsFile: good.OptionsFile},
		"no boot file":   {Loaded: true, Params: good.Params, OptionsFile: good.OptionsFile},
		"edited options": {Loaded: true, Params: good.Params, LoadFile: good.LoadFile, OptionsFile: "options nf-conntrack hashsize=1\n"},
	} {
		if m.InSync(a) {
			t.Errorf("%s: should be out of sync", name)
		}
	}
	// A param the kernel doesn't show can't be compared; the options file
	// stands in for it.
	if !m.InSync(Actual{Loaded: true, Params: map[string]string{"acct": "Y"}, LoadFile: good.LoadFile, OptionsFile: good.OptionsFile}) {
		t.Error("an unreadable param shouldn't count as different")
	}
	m.Persistent = false
	if !m.InSync(Actual{Loaded: true, Params: good.Params}) {
		t.Error("without persistent, the boot files don't matter")
	}
	gone := Module{Name: "dummy", Absent: true, Persistent: true}
	if !gone.InSync(Actual{}) || gone.InSync(Actual{Loaded: true}) || gone.InSync(Actual{LoadFile: "dummy\n"}) {
		t.Error("absent means unloaded, with no boot files")
	}
	if got := m.optionsContent(); got != "# Written by Conn3x.\noptions nf-conntrack hashsize=65536 acct=1\n" {
		t.Errorf("options = %q", got)
	}
}
