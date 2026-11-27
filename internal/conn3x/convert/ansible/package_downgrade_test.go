// Copyright (c) The Conn3x Authors
// SPDX-License-Identifier: MPL-2.0

package ansible

import (
	"strings"
	"testing"
)

// allow_downgrade changes nothing for a name with no version, so it drops;
// a name with a version stays for review (#1462, #1476).
func TestConvertPackageAllowDowngrade(t *testing.T) {
	const aptNote = "allow_downgrade dropped"
	for _, tc := range []struct {
		task   string
		review string // "" when the task converts
		note   bool
	}{
		{task: "package: {name: docker-ce, allow_downgrade: true}", note: true},
		{task: "package: {name: docker-ce, state: latest, allow_downgrade: true}", note: true},
		{task: "apt: {name: docker-ce, allow_downgrade: yes}", note: true},
		{task: "apt: {name: [docker-ce, containerd.io], state: latest, allow_downgrade: true}", note: true},
		{task: "dnf: {name: docker-ce, allow_downgrade: true}"},
		{task: "dnf5: {name: docker-ce, state: latest, allow_downgrade: true}"},
		{task: "package: {name: docker-ce, allow_downgrade: false}"},
		{task: "apt: {name: docker-ce, state: absent, allow_downgrade: true}"},
		{task: "dnf: {name: nginx-1.26.2, allow_downgrade: true}", review: "looks like a name with a version"},
		{task: "package: {name: nginx-1.26.2, allow_downgrade: true}", review: "looks like a name with a version"},
		{task: "apt: {name: 'docker-ce=5:27.*', allow_downgrade: true}", review: "cannot be a package step"},
	} {
		t.Run(tc.task, func(t *testing.T) {
			res := convertString(t, "- hosts: all\n  tasks:\n    - "+tc.task+"\n")
			hcl := string(res.HCL)
			if tc.review != "" {
				if res.Converted != 0 || !hasPackageReviewReason(res, tc.review) {
					t.Fatalf("converted %d, want review with %q: %+v\n%s", res.Converted, tc.review, res.Review, hcl)
				}
				return
			}
			if res.Converted == 0 || len(res.Review) != 0 {
				t.Fatalf("converted %d, review %+v:\n%s", res.Converted, res.Review, hcl)
			}
			if strings.Contains(hcl, "allow_downgrade =") {
				t.Errorf("allow_downgrade written as an argument:\n%s", hcl)
			}
			if got := strings.Contains(hcl, aptNote); got != tc.note {
				t.Errorf("note %v, want %v:\n%s", got, tc.note, hcl)
			}
		})
	}
}
