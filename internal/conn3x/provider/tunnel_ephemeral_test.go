// Copyright (c) The Conn3x Authors
// SPDX-License-Identifier: MPL-2.0

package provider

import (
	"io"
	"net"
	"strconv"
	"testing"
	"time"

	"github.com/zclconf/go-cty/cty"

	"github.com/opentofu/opentofu/internal/conn3x/transport/ssh/sshtest"
	"github.com/opentofu/opentofu/internal/providers"
)

// A tunnel opens a local port that reaches remote from the host, and
// closing it closes the port.
func TestSSHTunnel(t *testing.T) {
	echo, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer echo.Close()
	go func() {
		for {
			c, err := echo.Accept()
			if err != nil {
				return
			}
			go func() { defer c.Close(); _, _ = io.Copy(c, c) }()
		}
	}()
	s := sshtest.New(t)
	ssh := eosStep("conn3x_file", nil, map[string]cty.Value{
		"host": cty.StringVal(s.Host), "port": cty.NumberIntVal(int64(s.Port)), "user": cty.StringVal("ops"),
		"private_key_file": cty.StringVal(s.KeyFile(t)), "known_hosts_file": cty.StringVal(s.KnownHosts(t)),
	}).GetAttr("ssh")
	ty := tunnelSchema().Block.ImpliedType()
	vals := map[string]cty.Value{}
	for name, at := range ty.AttributeTypes() {
		vals[name] = cty.NullVal(at)
	}
	vals["remote"] = cty.StringVal(echo.Addr().String())
	vals["ssh"] = ssh
	cfg := cty.ObjectVal(vals)
	if d := validateTunnel(cfg); d.HasErrors() {
		t.Fatal(d.Err())
	}

	resp := openTunnel(ctx, providers.OpenEphemeralResourceRequest{TypeName: tunnelType, Config: cfg})
	if err := resp.Diagnostics.Err(); err != nil {
		t.Fatal(err)
	}
	port, _ := resp.Result.GetAttr("local_port").AsBigFloat().Int64()
	addr := net.JoinHostPort(resp.Result.GetAttr("local_host").AsString(), strconv.FormatInt(port, 10))
	conn, err := net.Dial("tcp", addr)
	if err != nil {
		t.Fatal(err)
	}
	_, _ = conn.Write([]byte("through"))
	buf := make([]byte, 7)
	if _, err := io.ReadFull(conn, buf); err != nil || string(buf) != "through" {
		t.Fatalf("read %q, %v", buf, err)
	}
	conn.Close()

	closeTunnel(providers.CloseEphemeralResourceRequest{TypeName: tunnelType, Private: resp.Private})
	if c, err := net.DialTimeout("tcp", addr, time.Second); err == nil {
		c.Close()
		t.Error("the port is still open after close")
	}

	vals["remote"] = cty.StringVal("no-port")
	if d := validateTunnel(cty.ObjectVal(vals)); !d.HasErrors() {
		t.Error("a remote without a port passed")
	}
}
