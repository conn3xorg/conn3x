// Copyright (c) The Conn3x Authors
// SPDX-License-Identifier: MPL-2.0

package ansible

import (
	"strings"
	"testing"
)

func hasPackageReviewReason(res Result, want string) bool {
	for _, r := range res.Review {
		if strings.Contains(r.Reason, want) {
			return true
		}
	}
	return false
}

// A name that upgrades every package, or that holds a glob, can never
// validate as a package step. The converter leaves the whole task for review
// instead of writing HCL that conn3x validate refuses (#1186).
func TestConvertPackageNameToReview(t *testing.T) {
	for _, mod := range []string{"apt", "dnf", "yum", "package"} {
		t.Run(mod+" star", func(t *testing.T) {
			res := convertString(t, "- hosts: all\n  tasks:\n    - "+mod+": {name: '*', state: latest}\n")
			if res.Converted != 0 {
				t.Errorf("converted %d steps, want 0:\n%s", res.Converted, res.HCL)
			}
			if !hasPackageReviewReason(res, "every package") {
				t.Errorf("no review item for a name that upgrades every package: %+v", res.Review)
			}
		})
	}
	t.Run("glob", func(t *testing.T) {
		res := convertString(t, "- hosts: all\n  tasks:\n    - apt: {name: nginx*, state: latest}\n")
		if res.Converted != 0 {
			t.Errorf("converted %d steps, want 0:\n%s", res.Converted, res.HCL)
		}
		if !hasPackageReviewReason(res, "cannot be a package step") {
			t.Errorf("no review item for a glob name: %+v", res.Review)
		}
	})
	t.Run("mixed list", func(t *testing.T) {
		res := convertString(t, "- hosts: all\n  tasks:\n    - apt: {name: [nginx, '*'], state: latest}\n")
		if res.Converted != 0 {
			t.Errorf("converted %d steps, want 0 so no partial list is written:\n%s", res.Converted, res.HCL)
		}
		if !hasPackageReviewReason(res, "every package") {
			t.Errorf("no review item for the mixed list: %+v", res.Review)
		}
	})
	// A name render couldn't fill keeps render's reason, not this check's.
	for name, want := range map[string]string{
		"'{{ web_package }}'":          `refers to "web_package", which isn't a play variable`,
		"'{% if a %}nginx{% endif %}'": "uses a Jinja expression the converter can't translate",
	} {
		t.Run("unfilled "+name, func(t *testing.T) {
			res := convertString(t, "- hosts: all\n  tasks:\n    - apt: {name: "+name+"}\n")
			if !hasPackageReviewReason(res, want) || hasPackageReviewReason(res, "cannot be a package step") {
				t.Errorf("review %+v, want %q", res.Review, want)
			}
		})
	}
	t.Run("plain name still converts", func(t *testing.T) {
		res := convertString(t, "- hosts: all\n  tasks:\n    - apt: {name: nginx, state: latest}\n")
		if res.Converted != 1 || len(res.Review) != 0 {
			t.Errorf("converted %d, review %+v, want 1 and none", res.Converted, res.Review)
		}
	})
}
