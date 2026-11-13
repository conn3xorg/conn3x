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

// A client that sends, shuts its write side, then reads still gets the
// reply, as through ssh -L.
func TestSSHTunnelHalfClose(t *testing.T) {
	svc, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer svc.Close()
	go func() {
		c, err := svc.Accept()
		if err != nil {
			return
		}
		defer c.Close()
		got, _ := io.ReadAll(c) // to EOF, then answer
		_, _ = c.Write(append([]byte("got "), got...))
	}()
	s := sshtest.New(t)
	ssh := eosStep("conn3x_file", nil, map[string]cty.Value{
		"host": cty.StringVal(s.Host), "port": cty.NumberIntVal(int64(s.Port)), "user": cty.StringVal("ops"),
		"private_key_file": cty.StringVal(s.KeyFile(t)), "known_hosts_file": cty.StringVal(s.KnownHosts(t)),
	}).GetAttr("ssh")
	vals := map[string]cty.Value{}
	for name, at := range tunnelSchema().Block.ImpliedType().AttributeTypes() {
		vals[name] = cty.NullVal(at)
	}
	vals["remote"], vals["ssh"] = cty.StringVal(svc.Addr().String()), ssh
	resp := openTunnel(ctx, providers.OpenEphemeralResourceRequest{TypeName: tunnelType, Config: cty.ObjectVal(vals)})
	if err := resp.Diagnostics.Err(); err != nil {
		t.Fatal(err)
	}
	defer closeTunnel(providers.CloseEphemeralResourceRequest{TypeName: tunnelType, Private: resp.Private})
	port, _ := resp.Result.GetAttr("local_port").AsBigFloat().Int64()
	conn, err := net.Dial("tcp", net.JoinHostPort("127.0.0.1", strconv.FormatInt(port, 10)))
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	_, _ = conn.Write([]byte("ping"))
	_ = conn.(*net.TCPConn).CloseWrite()
	_ = conn.SetReadDeadline(time.Now().Add(5 * time.Second))
	reply, err := io.ReadAll(conn)
	if string(reply) != "got ping" {
		t.Fatalf("reply %q, %v", reply, err)
	}
}

// Closing a tunnel doesn't wait for a forward still connecting to a remote
// that drops packets.
func TestSSHTunnelClosesWhileConnecting(t *testing.T) {
	s := sshtest.New(t)
	s.SetForwardDelay(30 * time.Second)
	ssh := eosStep("conn3x_file", nil, map[string]cty.Value{
		"host": cty.StringVal(s.Host), "port": cty.NumberIntVal(int64(s.Port)), "user": cty.StringVal("ops"),
		"private_key_file": cty.StringVal(s.KeyFile(t)), "known_hosts_file": cty.StringVal(s.KnownHosts(t)),
	}).GetAttr("ssh")
	vals := map[string]cty.Value{}
	for name, at := range tunnelSchema().Block.ImpliedType().AttributeTypes() {
		vals[name] = cty.NullVal(at)
	}
	vals["remote"], vals["ssh"] = cty.StringVal("127.0.0.1:9"), ssh
	resp := openTunnel(ctx, providers.OpenEphemeralResourceRequest{TypeName: tunnelType, Config: cty.ObjectVal(vals)})
	if err := resp.Diagnostics.Err(); err != nil {
		t.Fatal(err)
	}
	port, _ := resp.Result.GetAttr("local_port").AsBigFloat().Int64()
	conn, err := net.Dial("tcp", net.JoinHostPort("127.0.0.1", strconv.FormatInt(port, 10)))
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	time.Sleep(300 * time.Millisecond) // the forward is now waiting on its connect
	start := time.Now()
	closeTunnel(providers.CloseEphemeralResourceRequest{TypeName: tunnelType, Private: resp.Private})
	if took := time.Since(start); took > 5*time.Second {
		t.Fatalf("close took %s", took)
	}
}
