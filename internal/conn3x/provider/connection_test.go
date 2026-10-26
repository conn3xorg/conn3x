// Copyright (c) The Conn3x Authors
// SPDX-License-Identifier: MPL-2.0

package provider

import (
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"github.com/zclconf/go-cty/cty"

	"github.com/opentofu/opentofu/internal/conn3x/transport/ssh"
)

func sshBlock(attrs map[string]cty.Value) cty.Value {
	ty := connectionBlock().Block.ImpliedType()
	vals := map[string]cty.Value{}
	for name, at := range ty.AttributeTypes() {
		vals[name] = cty.NullVal(at)
	}
	for k, v := range attrs {
		vals[k] = v
	}
	return cty.ObjectVal(vals)
}

func TestSSHConfigFileFillsInAnAlias(t *testing.T) {
	dir := t.TempDir()
	key := filepath.Join(dir, "id_test")
	if err := os.WriteFile(key, []byte("PRIVATE KEY BYTES"), 0o600); err != nil {
		t.Fatal(err)
	}
	conf := filepath.Join(dir, "config")
	if err := os.WriteFile(conf, []byte(strings.Join([]string{
		"Host web1",
		"  HostName 203.0.113.10",
		"  User deploy",
		"  Port 2222",
		"  IdentityFile " + key,
		"  ProxyJump admin@bastion.example.com:2200,10.0.0.5",
		"  UserKnownHostsFile " + filepath.Join(dir, "known_hosts"),
	}, "\n")+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}

	cfg, err := sshConfig(sshBlock(map[string]cty.Value{"host": cty.StringVal("web1"), "ssh_config_file": cty.StringVal(conf)}))
	if err != nil {
		t.Fatal(err)
	}
	want := ssh.Config{
		Host: "203.0.113.10", Port: 2222, User: "deploy", PrivateKey: []byte("PRIVATE KEY BYTES"),
		KnownHostsFile: filepath.Join(dir, "known_hosts"),
		Jumps:          []ssh.Jump{{Host: "bastion.example.com", Port: 2200, User: "admin"}, {Host: "10.0.0.5", Port: 22}},
	}
	if !reflect.DeepEqual(cfg, want) {
		t.Fatalf("got  %+v\nwant %+v", cfg, want)
	}

	// What the ssh block says wins over the file.
	cfg, err = sshConfig(sshBlock(map[string]cty.Value{
		"host": cty.StringVal("web1"), "ssh_config_file": cty.StringVal(conf),
		"user": cty.StringVal("root"), "port": cty.NumberIntVal(22),
		"jump_hosts": cty.ListValEmpty(cty.String),
	}))
	if err != nil || cfg.User != "root" || cfg.Port != 22 || len(cfg.Jumps) != 0 {
		t.Fatalf("explicit settings lost: %+v, %v", cfg, err)
	}
}

// Without ssh_config_file, nothing is read from any SSH config, so a
// Host * entry can never reroute a connection by surprise.
func TestNoSSHConfigWithoutTheSetting(t *testing.T) {
	cfg, err := sshConfig(sshBlock(map[string]cty.Value{"host": cty.StringVal("web1"), "user": cty.StringVal("root")}))
	if err != nil || cfg.Host != "web1" || len(cfg.Jumps) != 0 {
		t.Fatalf("got %+v, %v", cfg, err)
	}
	if _, err := sshConfig(sshBlock(map[string]cty.Value{"host": cty.StringVal("web1")})); err == nil || !strings.Contains(err.Error(), "user") {
		t.Fatalf("missing user: %v", err)
	}
}

func TestJumpHosts(t *testing.T) {
	cfg, err := sshConfig(sshBlock(map[string]cty.Value{
		"host": cty.StringVal("10.0.1.5"), "user": cty.StringVal("deploy"),
		"jump_hosts": cty.ListVal([]cty.Value{cty.StringVal("bastion.example.com")}),
	}))
	if err != nil || !reflect.DeepEqual(cfg.Jumps, []ssh.Jump{{Host: "bastion.example.com", Port: 22}}) {
		t.Fatalf("got %+v, %v", cfg.Jumps, err)
	}
	if _, err := sshConfig(sshBlock(map[string]cty.Value{
		"host": cty.StringVal("10.0.1.5"), "user": cty.StringVal("deploy"),
		"jump_hosts": cty.ListVal([]cty.Value{cty.StringVal("user@")}),
	})); err == nil {
		t.Fatal("accepted a bad jump host")
	}
}

func TestPoolKeySeparatesJumpPaths(t *testing.T) {
	a := ssh.Config{Host: "10.0.1.5", User: "deploy", Jumps: []ssh.Jump{{Host: "bastion-a", Port: 22}}}
	b := a
	b.Jumps = []ssh.Jump{{Host: "bastion-b", Port: 22}}
	if poolKey(a, false, nil, false, false) == poolKey(b, false, nil, false, false) {
		t.Fatal("two jump paths share one pooled connection")
	}
}

// A ProxyJump hop that names another Host alias is resolved through the
// same file, as OpenSSH does, rather than dialled by its alias.
func TestProxyJumpResolvesAliases(t *testing.T) {
	dir := t.TempDir()
	key := filepath.Join(dir, "id_bastion")
	if err := os.WriteFile(key, []byte("BASTION KEY"), 0o600); err != nil {
		t.Fatal(err)
	}
	conf := filepath.Join(dir, "config")
	if err := os.WriteFile(conf, []byte(strings.Join([]string{
		"Host bastion",
		"  HostName 203.0.113.5",
		"  User jump",
		"Host bastion2",
		"  HostName 203.0.113.6",
		"  User jump2",
		"  Port 2200",
		"  IdentityFile " + key,
		"Host inner",
		"  HostName 10.0.0.9",
		"  User nobody",
		"  Port 9999",
		"  ProxyJump bastion2",
		"Host app-*",
		"  ProxyJump bastion",
		"Host db-*",
		"  ProxyJump ops@inner:2022,198.51.100.7",
	}, "\n")+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	for host, want := range map[string][]ssh.Jump{
		"app-1": {{Host: "203.0.113.5", Port: 22, User: "jump"}},
		// inner's own ProxyJump comes first; the user and port written in
		// the hop win over inner's entry.
		"db-1": {
			{Host: "203.0.113.6", Port: 2200, User: "jump2", PrivateKey: []byte("BASTION KEY")},
			{Host: "10.0.0.9", Port: 2022, User: "ops"},
			{Host: "198.51.100.7", Port: 22},
		},
	} {
		cfg, err := sshConfig(sshBlock(map[string]cty.Value{
			"host": cty.StringVal(host), "user": cty.StringVal("deploy"), "ssh_config_file": cty.StringVal(conf),
		}))
		if err != nil {
			t.Fatalf("%s: %v", host, err)
		}
		if !reflect.DeepEqual(cfg.Jumps, want) {
			t.Errorf("%s: jumps\ngot  %+v\nwant %+v", host, cfg.Jumps, want)
		}
	}

	// Explicit jump_hosts still win, and are used as written.
	cfg, err := sshConfig(sshBlock(map[string]cty.Value{
		"host": cty.StringVal("app-1"), "user": cty.StringVal("deploy"), "ssh_config_file": cty.StringVal(conf),
		"jump_hosts": cty.ListVal([]cty.Value{cty.StringVal("bastion")}),
	}))
	if err != nil || !reflect.DeepEqual(cfg.Jumps, []ssh.Jump{{Host: "bastion", Port: 22}}) {
		t.Fatalf("explicit jump_hosts: %+v, %v", cfg.Jumps, err)
	}

	// A ProxyJump loop is an error, not a hang.
	loop := filepath.Join(dir, "loop")
	_ = os.WriteFile(loop, []byte("Host a\n  ProxyJump b\nHost b\n  ProxyJump a\n"), 0o600)
	if _, err := sshConfig(sshBlock(map[string]cty.Value{
		"host": cty.StringVal("a"), "user": cty.StringVal("deploy"), "ssh_config_file": cty.StringVal(loop),
	})); err == nil {
		t.Fatal("accepted a ProxyJump loop")
	}
}
