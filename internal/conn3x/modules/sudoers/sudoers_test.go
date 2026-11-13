// Copyright (c) The Conn3x Authors
// SPDX-License-Identifier: MPL-2.0

package sudoers

import (
	"strings"
	"testing"
)

func TestContent(t *testing.T) {
	for want, r := range map[string]Rule{
		"%deploy ALL=(ALL) NOPASSWD: /usr/bin/systemctl restart app\n":     {Name: "deploy", Group: "deploy", Commands: []string{"/usr/bin/systemctl restart app"}, NoPassword: true},
		"alice web1=(postgres) /usr/bin/psql, /usr/bin/pg_dump\n":          {Name: "alice", User: "alice", Host: "web1", RunAs: "postgres", Commands: []string{"/usr/bin/psql", "/usr/bin/pg_dump"}},
		`ops ALL=(root:root) /usr/bin/env FOO\=1 /bin/echo a\,b\:c` + "\n": {Name: "ops", User: "ops", RunAs: "root:root", Commands: []string{"/usr/bin/env FOO=1 /bin/echo a,b:c"}},
	} {
		if err := r.Validate(); err != nil {
			t.Fatal(err)
		}
		if got := r.Content(); !strings.HasSuffix(got, want) {
			t.Errorf("content:\n%s\nwant it to end:\n%s", got, want)
		}
	}
	d := Rule{Name: "x", User: "x", Commands: []string{"ALL"}}.Desired()
	if d.Path != "/etc/sudoers.d/x" || d.Mode != "0440" || d.ValidateCommand != "visudo -cf %s" {
		t.Errorf("desired = %+v", d)
	}
}

func TestValidate(t *testing.T) {
	for _, r := range []Rule{
		{Name: "app.conf", User: "a", Commands: []string{"ALL"}},
		{Name: "app~", User: "a", Commands: []string{"ALL"}},
		{Name: "app", Commands: []string{"ALL"}},
		{Name: "app", User: "a", Group: "b", Commands: []string{"ALL"}},
		{Name: "app", User: "a b", Commands: []string{"ALL"}},
		{Name: "app", User: "a"},
		{Name: "app", User: "a", Commands: []string{"systemctl restart app"}},
		{Name: "app", User: "a", Commands: []string{"/bin/true\nroot ALL=(ALL) ALL"}},
		{Name: "app", User: "a", Commands: []string{"/bin/true # comment"}},
		{Name: "app", User: "a", Commands: []string{"ALL"}, RunAs: "root, alice"},
	} {
		if r.Validate() == nil {
			t.Errorf("%+v should be refused", r)
		}
	}
}
