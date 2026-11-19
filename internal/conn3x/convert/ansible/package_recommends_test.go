// Copyright (c) The Conn3x Authors
// SPDX-License-Identifier: MPL-2.0

package ansible

import (
	"strings"
	"testing"
)

// apt's install_recommends and dnf's install_weak_deps both become
// install_recommends.
func TestConvertInstallRecommends(t *testing.T) {
	for task, want := range map[string]string{
		"apt: {name: nginx, update_cache: true, cache_valid_time: 3600, install_recommends: false}": "install_recommends = false",
		"dnf: {name: nginx, install_weak_deps: false}":                                              "install_recommends = false",
		"apt: {name: nginx, install_recommends: yes}":                                               "install_recommends = true",
	} {
		res := convertString(t, "- hosts: all\n  tasks:\n    - "+task+"\n")
		if res.Converted != 1 || !strings.Contains(string(res.HCL), want) {
			t.Errorf("%s: converted %d, want %s in:\n%s", task, res.Converted, want, res.HCL)
		}
	}
}
