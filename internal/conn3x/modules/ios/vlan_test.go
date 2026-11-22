// Copyright (c) The Conn3x Authors
// SPDX-License-Identifier: MPL-2.0

package ios

import (
	"slices"
	"strings"
	"testing"
)

const vlans = `hostname sw1
!
vtp domain lab
vtp mode transparent
!
vlan 10
 name users
!
vlan 20,30-32
!
vlan 40
 name old
!
`

func TestVLANCommands(t *testing.T) {
	for name, tc := range map[string]struct {
		v    VLAN
		want []string
	}{
		"in sync":                {VLAN{ID: 10, Name: "users"}, nil},
		"in a list, no name":     {VLAN{ID: 31}, nil},
		"renamed":                {VLAN{ID: 10, Name: "staff"}, []string{"vlan 10", " name staff"}},
		"named from a list":      {VLAN{ID: 20, Name: "voice"}, []string{"vlan 20", " name voice"}},
		"back to the default":    {VLAN{ID: 40}, []string{"vlan 40", " no name"}},
		"new":                    {VLAN{ID: 50, Name: "guests"}, []string{"vlan 50", " name guests"}},
		"new, the default name":  {VLAN{ID: 60}, []string{"vlan 60"}},
		"33 isn't in 30-32 list": {VLAN{ID: 33}, []string{"vlan 33"}},
	} {
		if got := tc.v.Commands(vlans); !slices.Equal(got, tc.want) {
			t.Errorf("%s: Commands = %q, want %q", name, got, tc.want)
		}
		if got := tc.v.InSync(vlans); got != (tc.want == nil) {
			t.Errorf("%s: InSync = %v", name, got)
		}
	}
}

func TestVLANRemoveCommands(t *testing.T) {
	if got := (VLAN{ID: 10}).RemoveCommands(vlans); !slices.Equal(got, []string{"no vlan 10"}) {
		t.Errorf("named: %q", got)
	}
	if got := (VLAN{ID: 31}).RemoveCommands(vlans); !slices.Equal(got, []string{"no vlan 31"}) {
		t.Errorf("in a list: %q", got)
	}
	if got := (VLAN{ID: 99}).RemoveCommands(vlans); got != nil {
		t.Errorf("missing: %q", got)
	}
}

// In VTP server mode a change goes to the whole domain, so it's refused.
func TestVTPLocal(t *testing.T) {
	if err := VTPLocal(vlans); err != nil {
		t.Errorf("transparent: %v", err)
	}
	if err := VTPLocal("vtp mode off\n"); err != nil {
		t.Errorf("off: %v", err)
	}
	for _, config := range []string{"hostname sw1\n", "vtp domain lab\nvtp mode server\n", "vtp mode client\n", "interface Vlan1\n vtp mode transparent\n"} {
		if err := VTPLocal(config); err == nil || !strings.Contains(err.Error(), "every switch in the domain") {
			t.Errorf("%q: %v", config, err)
		}
	}
}

func TestVLANValidate(t *testing.T) {
	for _, ok := range []VLAN{{ID: 2}, {ID: 1001, Name: "a"}, {ID: 1006}, {ID: 4094, Name: strings.Repeat("x", 32)}} {
		if err := ok.Validate(); err != nil {
			t.Errorf("%+v: %v", ok, err)
		}
	}
	for _, bad := range []VLAN{{ID: 0}, {ID: 1}, {ID: 1002}, {ID: 1005}, {ID: 4095}, {ID: 10, Name: "two words"}, {ID: 10, Name: strings.Repeat("x", 33)}, {ID: 10, Name: "a?b"}, {ID: 10, Name: "us\u200bers"}, {ID: 10, Name: "\u202eusers"}, {ID: 10, Name: "café"}} {
		if err := bad.Validate(); err == nil {
			t.Errorf("%+v: no error", bad)
		}
	}
}
