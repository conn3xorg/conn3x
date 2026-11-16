// Copyright (c) The Conn3x Authors
// SPDX-License-Identifier: MPL-2.0

package ansible

import (
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
)

func TestReadInventoryRefuses(t *testing.T) {
	if _, err := ReadInventory(filepath.Join(t.TempDir(), "nope.ini")); !os.IsNotExist(err) {
		t.Errorf("missing: %v", err)
	}
	for name, c := range map[string]struct{ src, want string }{
		"nul.ini":     {"web1\x00\n", "has a NUL byte"},
		"vars.ini":    {"[web:vars]\nnovalue\n", "line 2: expected key=value"},
		"kind.ini":    {"[web:other]\nx\n", `line 2: unknown section kind "other"`},
		"quote.ini":   {"web1 a='open\n", "line 1:"},
		"range.ini":   {"web[1:x]\n", `line 1: host pattern "web[1:x]"`},
		"loop.ini":    {"[a:children]\nb\n[b:children]\na\n", "is a child of itself"},
		"bad.yml":     {"all: [\n", "bad.yml:"},
		"range.yml":   {"all:\n  hosts:\n    'web[3:1]': {}\n", `host pattern "web[3:1]"`},
		"child.yml":   {"all:\n  children:\n    web:\n      hosts:\n        'x]': {}\n", "a ] without a ["},
		"toomany.ini": {"h[0:99][0:999]\n", "it makes more than 10000 hosts"},
	} {
		p := filepath.Join(t.TempDir(), name)
		writeFile(t, p, c.src)
		if _, err := ReadInventory(p); err == nil || !strings.Contains(err.Error(), c.want) {
			t.Errorf("%s: %v, want %q", name, err, c.want)
		}
	}
}

func TestReadInventoryYAMLAndVarsDirs(t *testing.T) {
	dir := writeRole(t, map[string]string{
		"hosts.yml":                "all:\n  vars: { region: eu }\n  children:\n    web:\n      hosts:\n        web1: { ansible_host: 10.0.0.1 }\n        web2: {}\n",
		"group_vars/web/a.yml":     "tier: front\nlist: [1, 2]\n",
		"group_vars/web/b.yml":     "tier: edge\n",
		"group_vars/web/notes.txt": "tier: ignored\n",
		"group_vars/all.json":      "{\"dc\": \"one\"}\n",
		"group_vars/empty.yml":     "",
		"host_vars/web1.yml":       "rack: r1\n",
	})
	inv, err := ReadInventory(filepath.Join(dir, "hosts.yml"))
	if err != nil {
		t.Fatal(err)
	}
	web := inv.Group("web")
	if got := web.Names(); !slices.Equal(got, []string{"web1", "web2"}) {
		t.Errorf("names %v", got)
	}
	v := web.Vars("web1")
	if v["region"] != "eu" || v["tier"] != "edge" || v["dc"] != "one" || v["rack"] != "r1" || v["list"] != "" {
		t.Errorf("web1 vars %v", v)
	}
	if a := web.Addresses(); a["web1"] != "10.0.0.1" || a["web2"] != "web2" {
		t.Errorf("addresses %v", a)
	}
	if c, ok := web.Common("tier"); !ok || c != "edge" {
		t.Errorf("common tier %q, %v", c, ok)
	}
	if _, ok := web.Common("rack"); ok {
		t.Error("rack, set on one host, is common")
	}
	if got := web.Values("rack"); !slices.Equal(got, []string{"r1"}) {
		t.Errorf("values %v", got)
	}
	if got := inv.Ordered("all"); !slices.Contains(got, "web1") || !slices.Contains(got, "web2") {
		t.Errorf("ordered all %v", got)
	}
	if got := inv.Ordered("nosuch"); len(got) != 0 {
		t.Errorf("ordered for a missing group %v", got)
	}
	if !slices.Contains(inv.GroupNames(), "web") {
		t.Errorf("groups %v", inv.GroupNames())
	}

	// A vault file in group_vars stops the read.
	writeFile(t, filepath.Join(dir, "group_vars", "web", "c.yml"), "$ANSIBLE_VAULT;1.1;AES256\n00\n")
	if _, err := ReadInventory(filepath.Join(dir, "hosts.yml")); err == nil || !strings.Contains(err.Error(), "encrypted with Ansible Vault") {
		t.Errorf("vault: %v", err)
	}
	writeFile(t, filepath.Join(dir, "group_vars", "web", "c.yml"), "- [\n")
	if _, err := ReadInventory(filepath.Join(dir, "hosts.yml")); err == nil || !strings.Contains(err.Error(), "c.yml") {
		t.Errorf("bad YAML: %v", err)
	}
	writeFile(t, filepath.Join(dir, "group_vars", "web", "c.yml"), "")
	writeFile(t, filepath.Join(dir, "host_vars", "web2"), "- [\n")
	if _, err := ReadInventory(filepath.Join(dir, "hosts.yml")); err == nil || !strings.Contains(err.Error(), "web2") {
		t.Errorf("bad host_vars: %v", err)
	}
	// An empty YAML inventory has no hosts.
	p := filepath.Join(t.TempDir(), "empty.yaml")
	writeFile(t, p, "")
	if inv, err := ReadInventory(p); err != nil || len(inv.Ordered("all")) != 0 {
		t.Errorf("empty: %v", err)
	}
}

// AddHost takes a name as it is, and keeps the variables a host has.
func TestInventoryAddHost(t *testing.T) {
	inv := NewInventory()
	inv.AddHost("web", "web[1:2]", map[string]string{"a": "1"})
	inv.AddHost("web", "web[1:2]", map[string]string{"a": "2", "b": "3"})
	inv.AddHost("db", "web[1:2]", nil)
	g := inv.Group("web")
	if got := g.Names(); !slices.Equal(got, []string{"web[1:2]"}) {
		t.Errorf("names %v", got)
	}
	if v := g.Vars("web[1:2]"); v["a"] != "1" || v["b"] != "3" {
		t.Errorf("vars %v", v)
	}
	if got := inv.Ordered("all"); !slices.Equal(got, []string{"web[1:2]"}) {
		t.Errorf("all %v", got)
	}
}
