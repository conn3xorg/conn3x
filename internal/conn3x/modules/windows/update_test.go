// Copyright (c) The Conn3x Authors
// SPDX-License-Identifier: MPL-2.0

package windows

import (
	"strings"
	"testing"
)

func TestUpdateValidate(t *testing.T) {
	for _, ok := range []Update{{}, {Categories: []string{"SecurityUpdates", "DefinitionUpdates"}}, {Accept: []string{"KB5034441"}, Reject: []string{"KB890830"}}} {
		if err := ok.Validate(); err != nil {
			t.Errorf("%+v: %v", ok, err)
		}
	}
	for want, bad := range map[string]Update{
		"not a Windows Update category": {Categories: []string{"Security Updates"}},
		"not a KB number":               {Reject: []string{"5034441"}},
		"not a KB number ":              {Accept: []string{"KB5034441; rm -rf"}},
	} {
		if err := bad.Validate(); err == nil || !strings.Contains(err.Error(), strings.TrimSpace(want)) {
			t.Errorf("%+v: err = %v", bad, err)
		}
	}
}

// The scripts get category IDs, the default when none are named, and empty
// lists rather than nulls.
func TestUpdateArgs(t *testing.T) {
	a := Update{}.args()
	if got := a["categories"].([]string); len(got) != 2 || got[0] != UpdateCategories["CriticalUpdates"] || got[1] != UpdateCategories["SecurityUpdates"] {
		t.Errorf("default categories = %v", got)
	}
	if a["accept"] == nil || a["reject"] == nil || len(a["accept"].([]string)) != 0 {
		t.Errorf("lists = %v, %v", a["accept"], a["reject"])
	}
}
