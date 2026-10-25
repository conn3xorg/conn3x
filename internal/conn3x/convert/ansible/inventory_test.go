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
