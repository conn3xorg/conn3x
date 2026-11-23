// Copyright (c) The Conn3x Authors
// SPDX-License-Identifier: MPL-2.0

package pkg

import (
	"strings"
	"testing"
)

// zypper -x search's lines, as openSUSE Leap 15.6 prints them: one per
// repository, without a 0: epoch.
func TestZypperNewest(t *testing.T) {
	out := `<solvable-list>
<solvable status="installed" name="tree" kind="package" edition="1.7.0-150000.3.2.1" arch="aarch64" repository="Update"/>
<solvable status="other-version" name="tree" kind="package" edition="1.7.0-1.30" arch="aarch64" repository="Main"/>
<solvable status="not-installed" name="tree-doc" kind="package" edition="9.9-1" arch="noarch" repository="Main"/>
</solvable-list>`
	if got := zypperNewest(out, "tree"); got != "0:1.7.0-150000.3.2.1" {
		t.Errorf("newest = %q", got)
	}
	if got := zypperNewest(out, "nginx"); got != "" {
		t.Errorf("not listed = %q", got)
	}
}

func TestDetectSUSE(t *testing.T) {
	for _, release := range []string{"ID=\"opensuse-leap\"\nID_LIKE=\"suse opensuse\"\n", "ID=\"sles\"\nID_LIKE=\"suse\"\n", "ID=\"opensuse-tumbleweed\"\n"} {
		h := &scriptedHost{answers: []answer{{"/etc/os-release", ok(release)}}}
		if got, err := DetectFamily(ctx, h); err != nil || got != SUSE {
			t.Errorf("%q: %v, %v", release, got, err)
		}
	}
}

func TestSUSEApplyAndHold(t *testing.T) {
	yes := true
	for name, tc := range map[string]struct {
		d    Desired
		want string
	}{
		"install":    {Desired{Name: "tree", State: Present}, "zypper -n -q install 'tree'"},
		"pin":        {Desired{Name: "tree", State: Present, Version: "1.7.0"}, "zypper -n -q install --oldpackage 'tree=1.7.0'"},
		"recommends": {Desired{Name: "tree", State: Present, InstallRecommends: &yes}, "zypper -n -q install --recommends 'tree'"},
		"latest":     {Desired{Name: "tree", State: Latest}, "zypper -n -q update 'tree'"},
		"remove":     {Desired{Name: "tree", State: Absent}, "zypper -n -q remove 'tree'"},
	} {
		h := &scriptedHost{answers: []answer{{"zypper", ok("")}}}
		if err := Apply(ctx, h, SUSE, tc.d); err != nil {
			t.Errorf("%s: %v", name, err)
			continue
		}
		if got := strings.Join(h.ran, "\n"); !strings.Contains(got, tc.want) {
			t.Errorf("%s: ran %q, want %q", name, got, tc.want)
		}
	}
	locks := "\n# | Name | Type    | Repository | Comment\n--+------+---------+------------+--------\n1 | tree | package | (any)      | \n"
	if !heldIn(SUSE, locks, "tree") || heldIn(SUSE, locks, "tre") || heldIn(SUSE, "There are no package locks defined.\n", "tree") {
		t.Error("zypper locks read wrong")
	}
	if !lockHeld(errString("System management is locked by the application with pid 540 (zypper).")) {
		t.Error("zypper's lock isn't waited out")
	}
}

type errString string

func (e errString) Error() string { return string(e) }
