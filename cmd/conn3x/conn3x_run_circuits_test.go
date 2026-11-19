// Copyright (c) The Conn3x Authors
// SPDX-License-Identifier: MPL-2.0

package main

import (
	"github.com/opentofu/opentofu/internal/configs"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/zclconf/go-cty/cty"
)

func TestCircuitInventory(t *testing.T) {
	dir := t.TempDir()
	write := func(name, src string) {
		t.Helper()
		if err := os.WriteFile(filepath.Join(dir, name), []byte(src), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	write("web.circuit.hcl", `circuit "web" {
  hosts = {
    web1 = "192.0.2.11"
    web2 = { address = "192.0.2.12", user = "deploy", port = 2222, role = "edge" }
  }
  ssh {
    user             = "ops"
    private_key_file = "~/.ssh/id_ed25519"
    known_hosts_file = "~/.ssh/known_hosts_lab"
    become           = true
  }
  step "motd" {
    file {
      path    = "/etc/motd"
      content = "hi"
    }
  }
}
`)
	write("main.tf", `terraform {}
circuit "db" {
  hosts = { db1 = "192.0.2.21" }
  ssh {
    user = "dba"
  }
}
`)
	inv, err := circuitInventory(dir)
	if err != nil {
		t.Fatal(err)
	}
	if got := inv.Ordered("web"); !slices.Equal(got, []string{"web1", "web2"}) {
		t.Errorf("web: %q", got)
	}
	if got := inv.Ordered("db"); !slices.Equal(got, []string{"db1"}) {
		t.Errorf("db: %q", got)
	}
	all := inv.Group("all")
	o := runOptions{}
	ssh := o.sshFor("web2", all.Vars("web2"))
	want := map[string]cty.Value{
		"host": cty.StringVal("192.0.2.12"), "user": cty.StringVal("deploy"), "port": cty.NumberIntVal(2222),
		"private_key_file": cty.StringVal("~/.ssh/id_ed25519"), "known_hosts_file": cty.StringVal("~/.ssh/known_hosts_lab"), "become": cty.True,
	}
	for k, v := range want {
		if !ssh[k].RawEquals(v) {
			t.Errorf("web2 ssh %s = %#v, want %#v", k, ssh[k], v)
		}
	}
	if u := o.sshFor("db1", all.Vars("db1"))["user"]; !u.RawEquals(cty.StringVal("dba")) {
		t.Errorf("db1 user %#v", u)
	}

	for name, src := range map[string]string{
		"var":              `circuit "x" { hosts = var.hosts }`,
		"jump":             "circuit \"x\" {\n  hosts = { a = \"192.0.2.1\" }\n  ssh {\n    jump_hosts = [\"b\"]\n  }\n}\n",
		"no addr":          `circuit "x" { hosts = { a = { user = "u" } } }`,
		"ssh func":         "circuit \"x\" {\n  hosts = { a = \"192.0.2.1\" }\n  ssh {\n    user = lower(\"OPS\")\n  }\n}\n",
		"two ways":         "circuit \"x\" {\n  hosts = { a = \"192.0.2.1\" }\n  ssh {\n    user = \"one\"\n  }\n}\ncircuit \"y\" {\n  hosts = { a = \"192.0.2.1\" }\n  ssh {\n    user = \"two\"\n  }\n}\n",
		"two addresses":    "circuit \"x\" {\n  hosts = { a = \"192.0.2.1\" }\n}\ncircuit \"y\" {\n  hosts = { a = \"192.0.2.2\" }\n}\n",
		"two proxies":      "circuit \"x\" {\n  hosts = { a = \"192.0.2.1\" }\n  ssh {\n    proxy_command = [\"a\"]\n  }\n}\ncircuit \"y\" {\n  hosts = { a = \"192.0.2.1\" }\n  ssh {\n    proxy_command = [\"b\"]\n  }\n}\n",
		"no hosts":         `circuit "x" {}`,
		"hosts a list":     `circuit "x" { hosts = ["192.0.2.1"] }`,
		"host null":        `circuit "x" { hosts = { a = null } }`,
		"host a list":      `circuit "x" { hosts = { a = ["192.0.2.1"] } }`,
		"host user null":   `circuit "x" { hosts = { a = { address = "192.0.2.1", user = null } } }`,
		"ssh block inside": "circuit \"x\" {\n  hosts = { a = \"192.0.2.1\" }\n  ssh {\n    agent {}\n  }\n}\n",
		"ssh user a list":  "circuit \"x\" {\n  hosts = { a = \"192.0.2.1\" }\n  ssh {\n    user = [\"u\"]\n  }\n}\n",
		"proxy func":       "circuit \"x\" {\n  hosts = { a = \"192.0.2.1\" }\n  ssh {\n    proxy_command = split(\" \", \"aws ssm\")\n  }\n}\n",
		"proxy with null":  "circuit \"x\" {\n  hosts = { a = \"192.0.2.1\" }\n  ssh {\n    proxy_command = [\"aws\", null]\n  }\n}\n",
	} {
		d := t.TempDir()
		if err := os.WriteFile(filepath.Join(d, "c.circuit.hcl"), []byte(src), 0o644); err != nil {
			t.Fatal(err)
		}
		if _, err := circuitInventory(d); err == nil || !strings.Contains(err.Error(), "circuit \"") {
			t.Errorf("%s: %v", name, err)
		}
	}
	if _, err := circuitInventory(t.TempDir()); err == nil || !strings.Contains(err.Error(), "no circuit") {
		t.Errorf("empty dir: %v", err)
	}
	broken := t.TempDir()
	if err := os.WriteFile(filepath.Join(broken, "main.tf"), []byte(`circuit "x" {`), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := circuitInventory(broken); err == nil || !strings.Contains(err.Error(), "Unclosed configuration block") {
		t.Errorf("a file that doesn't parse: %v", err)
	}
	if err := circuitsDirExists(filepath.Join(broken, "missing")); err == nil {
		t.Error("-circuits accepted a directory that isn't there")
	}
}

// Key and known_hosts paths relative to the circuit resolve against its
// directory, so -circuits infra from the repository root finds them.
func TestCircuitInventoryRelativePaths(t *testing.T) {
	dir := t.TempDir()
	src := "circuit \"web\" {\n  hosts = {\n    web1 = \"192.0.2.11\"\n    web2 = { address = \"192.0.2.12\", private_key_file = \"keys/web2\" }\n    web3 = { address = \"192.0.2.13\", private_key_file = \"/etc/conn3x/web3\" }\n  }\n  ssh {\n    private_key_file = \"./id_ed25519\"\n    known_hosts_file = \"known_hosts\"\n  }\n}\n"
	if err := os.WriteFile(filepath.Join(dir, "main.circuit.hcl"), []byte(src), 0o644); err != nil {
		t.Fatal(err)
	}
	inv, err := circuitInventory(dir)
	if err != nil {
		t.Fatal(err)
	}
	all := inv.Group("all")
	o := runOptions{}
	for host, want := range map[string][2]string{
		"web1": {filepath.Join(dir, "id_ed25519"), filepath.Join(dir, "known_hosts")},
		"web2": {filepath.Join(dir, "keys/web2"), filepath.Join(dir, "known_hosts")},
		"web3": {"/etc/conn3x/web3", filepath.Join(dir, "known_hosts")},
	} {
		ssh := o.sshFor(host, all.Vars(host))
		if got := ssh["private_key_file"]; !got.RawEquals(cty.StringVal(want[0])) {
			t.Errorf("%s private_key_file = %#v, want %q", host, got, want[0])
		}
		if got := ssh["known_hosts_file"]; !got.RawEquals(cty.StringVal(want[1])) {
			t.Errorf("%s known_hosts_file = %#v, want %q", host, got, want[1])
		}
	}
}

func TestRunProxyCommand(t *testing.T) {
	dir := t.TempDir()
	src := "circuit \"x\" {\n  hosts = { a = \"i-0abc\" }\n  ssh {\n    proxy_command = [\"aws\", \"ssm\", \"start-session\", \"--target\", \"%h\"]\n  }\n}\n"
	if err := os.WriteFile(filepath.Join(dir, "main.circuit.hcl"), []byte(src), 0o600); err != nil {
		t.Fatal(err)
	}
	inv, err := circuitInventory(dir)
	if err != nil {
		t.Fatal(err)
	}
	want := cty.ListVal([]cty.Value{cty.StringVal("aws"), cty.StringVal("ssm"), cty.StringVal("start-session"), cty.StringVal("--target"), cty.StringVal("%h")})
	if got := (runOptions{}).sshFor("a", inv.Group("all").Vars("a"))["proxy_command"]; !got.RawEquals(want) {
		t.Errorf("-circuits proxy_command = %#v", got)
	}

	iap := []string{"gcloud", "compute", "start-iap-tunnel", "%h", "%p", "--listen-on-stdin", "--zone", "us-central1-a"}
	for name, vars := range map[string]map[string]string{
		"common args": {"ansible_ssh_common_args": `-o ProxyCommand="gcloud compute start-iap-tunnel %h %p --listen-on-stdin --zone us-central1-a"`},
		"joined -o":   {"ansible_ssh_common_args": `-o StrictHostKeyChecking=no '-oProxyCommand=gcloud compute start-iap-tunnel %h %p --listen-on-stdin --zone us-central1-a'`},
		"space form":  {"ansible_ssh_extra_args": `-o "proxycommand gcloud compute start-iap-tunnel %h %p --listen-on-stdin --zone us-central1-a"`},
	} {
		got, err := proxyCommandOf(vars)
		if err != nil || !slices.Equal(got, iap) {
			t.Errorf("%s: %q, %v", name, got, err)
		}
	}
	if got, err := proxyCommandOf(map[string]string{"ansible_ssh_common_args": "-o ServerAliveInterval=30"}); err != nil || got != nil {
		t.Errorf("no ProxyCommand: %q, %v", got, err)
	}
	if _, err := proxyCommandOf(map[string]string{"ansible_ssh_common_args": `-o ProxyCommand="nc %h %p | tee log"`}); err == nil {
		t.Error("a ProxyCommand that needs a shell was accepted")
	}

	bad := "circuit \"x\" {\n  hosts = { a = \"b\" }\n  ssh {\n    proxy_command = \"aws ssm\"\n  }\n}\n"
	if err := os.WriteFile(filepath.Join(dir, "main.circuit.hcl"), []byte(bad), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := circuitInventory(dir); err == nil || !strings.Contains(err.Error(), "list of strings") {
		t.Errorf("a string proxy_command: %v", err)
	}
}

// ansible_become takes Ansible's true values, -become wins, and a become
// user other than root is refused.
func TestRunAnsibleBecome(t *testing.T) {
	for v, want := range map[string]bool{"true": true, "yes": true, "True": true, "1": true, "false": false, "no": false, "": false} {
		got := (runOptions{}).sshFor("a", map[string]string{"ansible_become": v})["become"]
		if want != (got == cty.True) {
			t.Errorf("ansible_become=%q: become %#v", v, got)
		}
	}
	if got := (runOptions{become: true}).sshFor("a", map[string]string{"ansible_become": "false"})["become"]; got != cty.True {
		t.Errorf("-become with ansible_become=false: %#v", got)
	}
	if _, err := becomeOf(map[string]string{"ansible_become": "yes", "ansible_become_user": "postgres"}); err == nil {
		t.Error("ansible_become_user=postgres was accepted")
	}
	if b, err := becomeOf(map[string]string{"ansible_become": "yes", "ansible_become_user": "root"}); err != nil || !b {
		t.Errorf("ansible_become_user=root: %v, %v", b, err)
	}
	for _, v := range []string{"{{ use_sudo }}", "maybe"} {
		if _, err := becomeOf(map[string]string{"ansible_become": v}); err == nil {
			t.Errorf("ansible_become=%q was accepted", v)
		}
	}
	if _, err := becomeOf(map[string]string{"ansible_become": "yes", "ansible_become_method": "su"}); err == nil {
		t.Error("ansible_become_method=su was accepted")
	}
	if b, err := becomeOf(map[string]string{"ansible_become": "yes", "ansible_become_method": "sudo"}); err != nil || !b {
		t.Errorf("ansible_become_method=sudo: %v, %v", b, err)
	}
	if b, err := becomeOf(map[string]string{"ansible_become_user": "postgres"}); err != nil || b {
		t.Errorf("a become user without ansible_become: %v, %v", b, err)
	}
}

// An Ansible module name -m doesn't know gets a hint, not a silent alias,
// and none of the hints shadows a real module.
func TestRunAnsibleModuleHints(t *testing.T) {
	for name := range ansibleModuleHints {
		if _, ok := configs.Conn3xStepModules()[name]; ok {
			t.Errorf("%q is a Conn3x module, so its hint would never show", name)
		}
	}
	for _, want := range []string{"package", "service", "line", "file"} {
		if _, ok := configs.Conn3xStepModules()[want]; !ok {
			t.Errorf("a hint points at -m %s, which isn't a module", want)
		}
	}
}
