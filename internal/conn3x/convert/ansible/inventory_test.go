// Copyright (c) The Conn3x Authors
// SPDX-License-Identifier: MPL-2.0

package ansible

import (
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
)

func writeFile(t *testing.T, path, content string) {
	t.Helper()
	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}
}

func TestReadInventory(t *testing.T) {
	for _, file := range []string{"hosts.ini", "hosts.yml"} {
		inv, err := ReadInventory(filepath.Join("testdata", "inv", file))
		if err != nil {
			t.Fatalf("%s: %v", file, err)
		}
		web := inv.Group("web")
		if want := map[string]string{"web1": "203.0.113.10", "web2": "203.0.113.11"}; !reflect.DeepEqual(web.Addresses(), want) {
			t.Errorf("%s: web = %v", file, web.Addresses())
		}
		if _, ok := web.Common("ansible_user"); ok {
			t.Errorf("%s: web hosts disagree on ansible_user, but Common said they agree", file)
		}
		db := inv.Group("db")
		if u, ok := db.Common("ansible_user"); !ok || u != "admin" {
			t.Errorf("%s: db user = %q, %v", file, u, ok)
		}
		if got := inv.Group("prod").Addresses(); len(got) != 3 || got["db1.example.com"] != "db1.example.com" {
			t.Errorf("%s: prod = %v", file, got)
		}
		if got := inv.Group("all").Addresses(); len(got) != 3 {
			t.Errorf("%s: all = %v", file, got)
		}
		if inv.Group("nope") != nil {
			t.Errorf("%s: found a group that isn't there", file)
		}
	}
}

func TestConvertWithInventory(t *testing.T) {
	inv, err := ReadInventory(filepath.Join("testdata", "inv", "hosts.ini"))
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(t.TempDir(), "play.yml")
	writeFile(t, path, `- name: Databases
  hosts: db
  tasks:
    - package: {name: postgresql}
- name: Web
  hosts: web
  tasks:
    - package: {name: nginx}
`)
	res, err := ConvertWith(path, Options{Inventory: inv})
	if err != nil {
		t.Fatal(err)
	}
	out := string(res.HCL)
	for _, want := range []string{
		`hosts = {
    "db1.example.com" = "db1.example.com"
  }`,
		`user             = "admin"`,
		`port             = 2222`,
		`web1 = "203.0.113.10"`,
		`TODO(convert): Play "web" (play.yml line 5) has hosts with different ansible_user (deploy`,
		`variable "ssh_user"`,
	} {
		if !strings.Contains(out, want) {
			t.Errorf("output is missing %q:\n%s", want, out)
		}
	}
	if strings.Contains(out, `variable "db_hosts"`) || strings.Contains(out, `variable "web_hosts"`) {
		t.Errorf("hosts variables left in although the inventory resolves them:\n%s", out)
	}
	if res.Converted != 2 || len(res.Review) != 1 {
		t.Errorf("converted %d, review %+v", res.Converted, res.Review)
	}
}

// group_vars/ and host_vars/ beside the inventory outrank the inventory
// file's own variables, as in Ansible: group_vars/all over every group in
// the file, a deeper group over a shallower one, and host_vars over all.
func TestReadInventoryVarsDirs(t *testing.T) {
	inv, err := ReadInventory(filepath.Join("testdata", "invdirs", "hosts.ini"))
	if err != nil {
		t.Fatal(err)
	}
	web := inv.Group("web")
	want := map[string]string{"ansible_host": "203.0.113.10", "role": "from-web", "region": "us", "port": "8080", "tier": "host_vars"}
	if got := web.Vars("web1"); !reflect.DeepEqual(got, want) {
		t.Errorf("web1 = %v, want %v", got, want)
	}
	if got := web.Vars("web2")["tier"]; got != "" {
		t.Errorf("web2's tier = %q, want none", got)
	}

	dir := t.TempDir()
	writeFile(t, filepath.Join(dir, "hosts.ini"), "[web]\nweb1\n")
	if err := os.Mkdir(filepath.Join(dir, "group_vars"), 0o755); err != nil {
		t.Fatal(err)
	}
	writeFile(t, filepath.Join(dir, "group_vars", "web.yml"), "$ANSIBLE_VAULT;1.1;AES256\n3132\n")
	if _, err := ReadInventory(filepath.Join(dir, "hosts.ini")); err == nil || !strings.Contains(err.Error(), "encrypted with Ansible Vault") {
		t.Errorf("an encrypted group_vars file: %v", err)
	}
}

func TestInventoryHostRanges(t *testing.T) {
	for pattern, want := range map[string]string{
		"web[01:03]":            "web01,web02,web03",
		"web[8:10].example.com": "web8.example.com,web9.example.com,web10.example.com",
		"db-[a:c]":              "db-a,db-b,db-c",
		"n[1:9:4]":              "n1,n5,n9",
		"r[1:2]-[a:b]":          "r1-a,r1-b,r2-a,r2-b",
		"plain":                 "plain",
	} {
		got, err := expandRange(pattern)
		if err != nil || strings.Join(got, ",") != want {
			t.Errorf("%s = %v, %v; want %s", pattern, got, err, want)
		}
	}
	for _, bad := range []string{"web[3:1]", "web[1:x]", "web[01]", "web[1:2", "web]", "web[1:5:0]", "web[0:99999]", "db-[a:cc]"} {
		if _, err := expandRange(bad); err == nil {
			t.Errorf("%s should be refused", bad)
		}
	}
	dir := t.TempDir()
	writeFile(t, filepath.Join(dir, "hosts.ini"), "[web]\nweb[1:2] ansible_user=deploy\n")
	inv, err := ReadInventory(filepath.Join(dir, "hosts.ini"))
	if err != nil {
		t.Fatal(err)
	}
	if got := inv.Group("web").Names(); strings.Join(got, ",") != "web1,web2" || inv.Group("web").Vars("web2")["ansible_user"] != "deploy" {
		t.Errorf("web = %v", got)
	}
}

// A playbook converted with -i finds values the inventory and its
// group_vars set for every host in the play; the play's own vars win.
func TestConvertUsesInventoryVars(t *testing.T) {
	dir := t.TempDir()
	writeFile(t, filepath.Join(dir, "hosts.ini"), "[web]\nweb1\nweb2\n\n[web:vars]\nmotd=managed by conn3x\nport=8080\n")
	if err := os.Mkdir(filepath.Join(dir, "group_vars"), 0o755); err != nil {
		t.Fatal(err)
	}
	writeFile(t, filepath.Join(dir, "group_vars", "web.yml"), "site_root: /srv/site\n")
	writeFile(t, filepath.Join(dir, "play.yml"), `- hosts: web
  vars:
    port: 9090
  tasks:
    - name: motd
      copy: { dest: /etc/motd, content: "{{ motd }}\n" }
    - name: root
      file: { path: "{{ site_root }}", state: directory }
    - name: port
      copy: { dest: /etc/port, content: "{{ port }}\n" }
`)
	inv, err := ReadInventory(filepath.Join(dir, "hosts.ini"))
	if err != nil {
		t.Fatal(err)
	}
	res, err := ConvertWith(filepath.Join(dir, "play.yml"), Options{Inventory: inv})
	if err != nil {
		t.Fatal(err)
	}
	hcl := string(res.HCL)
	for _, want := range []string{"managed by conn3x", `path = "/srv/site"`, "9090"} {
		if !strings.Contains(hcl, want) {
			t.Errorf("missing %q:\n%s", want, hcl)
		}
	}
	if res.Converted != 3 || len(res.Review) != 0 {
		t.Errorf("converted %d, review %v", res.Converted, res.Review)
	}
}
