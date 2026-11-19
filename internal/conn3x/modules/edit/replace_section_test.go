// Copyright (c) The Conn3x Authors
// SPDX-License-Identifier: MPL-2.0

package edit

import "testing"

// after and before limit the edit to one section, as Ansible's replace does.
func TestReplaceSection(t *testing.T) {
	const vhosts = "<VirtualHost *:80>\nLog off\n</VirtualHost>\n<VirtualHost *:443>\nLog off\n</VirtualHost>\nLog off\n"
	for name, c := range map[string]struct {
		r    Replace
		want string
	}{
		"both: first section only": {
			Replace{Regexp: "^Log off$", With: "Log on", After: `<VirtualHost \*:80>`, Before: "</VirtualHost>"},
			"<VirtualHost *:80>\nLog on\n</VirtualHost>\n<VirtualHost *:443>\nLog off\n</VirtualHost>\nLog off\n",
		},
		"after alone: to the end": {
			Replace{Regexp: "^Log off$", With: "Log on", After: `<VirtualHost \*:443>`},
			"<VirtualHost *:80>\nLog off\n</VirtualHost>\n<VirtualHost *:443>\nLog on\n</VirtualHost>\nLog on\n",
		},
		"before alone: up to the last match": {
			Replace{Regexp: "^Log off$", With: "Log on", Before: "</VirtualHost>"},
			"<VirtualHost *:80>\nLog on\n</VirtualHost>\n<VirtualHost *:443>\nLog on\n</VirtualHost>\nLog off\n",
		},
		"markers that don't match leave it alone": {
			Replace{Regexp: "^Log off$", With: "Log on", After: "<Directory>"},
			vhosts,
		},
		"a marker's alternation stays inside it": {
			Replace{Regexp: "^Log off$", With: "Log on", After: `nope|<VirtualHost \*:443>`, Before: "</VirtualHost>"},
			"<VirtualHost *:80>\nLog off\n</VirtualHost>\n<VirtualHost *:443>\nLog on\n</VirtualHost>\nLog off\n",
		},
	} {
		got, err := ApplyReplace(vhosts, c.r)
		if err != nil || got != c.want {
			t.Errorf("%s: %v\n%q\nwant\n%q", name, err, got, c.want)
		}
	}
	if err := (Replace{Regexp: "x", With: "y", After: "("}).Validate(); err == nil {
		t.Error("a bad after was accepted")
	}
}
