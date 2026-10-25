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
	if poolKey(a, false, nil) == poolKey(b, false, nil) {
		t.Fatal("two jump paths share one pooled connection")
	}
}
