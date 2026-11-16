// Copyright (c) The Conn3x Authors
// SPDX-License-Identifier: MPL-2.0

package agent

import (
	"bytes"
	"compress/gzip"
	"errors"
	"testing"

	"github.com/opentofu/opentofu/internal/conn3x/agent/agentpb"
)

// scripted is an agent that says hello and answers each request with
// reply's envelope.
func scripted(t *testing.T, reply func(req *agentpb.Envelope) *agentpb.Envelope) *Client {
	t.Helper()
	conn, end := pipes()
	go func() {
		defer end.Close()
		if agentpb.WriteFrame(end, &agentpb.Envelope{Hello: &agentpb.Hello{Version: agentpb.ProtocolVersion}}) != nil {
			return
		}
		for {
			req, err := agentpb.ReadFrame(end)
			if err != nil {
				return
			}
			e := reply(req)
			e.ID = req.ID
			if agentpb.WriteFrame(end, e) != nil {
				return
			}
		}
	}()
	c, err := NewClient(ctx, conn)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { c.Close() })
	return c
}

// A reply of the wrong kind is a protocol error, never a zero result.
func TestWrongReplyIsProtocolError(t *testing.T) {
	c := scripted(t, func(*agentpb.Envelope) *agentpb.Envelope { return &agentpb.Envelope{Cancel: &agentpb.Cancel{}} })
	if _, err := c.Run(ctx, "true", nil); !errors.Is(err, ErrProtocol) {
		t.Errorf("Run: %v", err)
	}
	if _, err := c.ReadFile(ctx, "/etc/hosts"); !errors.Is(err, ErrProtocol) {
		t.Errorf("ReadFile: %v", err)
	}
	if _, err := c.ReadUnit(ctx, "sshd.service"); !errors.Is(err, ErrProtocol) {
		t.Errorf("ReadUnit: %v", err)
	}
}

func TestReplies(t *testing.T) {
	c := scripted(t, func(req *agentpb.Envelope) *agentpb.Envelope {
		switch {
		case req.ReadUnit != nil:
			return &agentpb.Envelope{Unit: &agentpb.UnitProps{Props: map[string]string{"Id": req.ReadUnit.Unit}}}
		case req.ReadFile != nil:
			return &agentpb.Envelope{Error: &agentpb.Error{Code: agentpb.CodeUnsupported, Message: "owner has no name"}}
		}
		return &agentpb.Envelope{Error: &agentpb.Error{Code: agentpb.CodeInternal, Message: "boom"}}
	})
	if props, err := c.ReadUnit(ctx, "sshd.service"); err != nil || props["Id"] != "sshd.service" {
		t.Errorf("ReadUnit: %v, %v", props, err)
	}
	if _, err := c.ReadFile(ctx, "/x"); !errors.Is(err, errors.ErrUnsupported) || err.Error() != "conn3x agent: owner has no name: unsupported operation" {
		t.Errorf("unsupported: %v", err)
	}
	if _, err := c.Run(ctx, "true", nil); err == nil || err.Error() != "conn3x agent: internal error: boom" || errors.Is(err, errors.ErrUnsupported) {
		t.Errorf("internal: %v", err)
	}
}

func TestCleanVersion(t *testing.T) {
	for in, want := range map[string]string{"": "dev", "v1.2.3-rc.1+abc": "v1.2.3-rc.1+abc", "1.0/../x y": "1.0_.._x_y"} {
		if got := cleanVersion(in); got != want {
			t.Errorf("%q: %q, want %q", in, got, want)
		}
	}
}

func TestParseProbeAndGunzip(t *testing.T) {
	p := parseProbe([]byte("arch x86_64\nfapolicyd\ndir abc exec /home/u/.cache/conn3x\ndir - noexec /tmp/x y\ndir short\n"))
	if p.arch != "x86_64" || !p.fapolicyd || p.gunzip || len(p.dirs) != 2 || !p.dirs[0].exec || p.dirs[1].exec || p.dirs[1].path != "/tmp/x y" {
		t.Errorf("got %+v", p)
	}
	var gz bytes.Buffer
	w := gzip.NewWriter(&gz)
	_, _ = w.Write([]byte("agent"))
	_ = w.Close()
	if b, err := gunzip(gz.Bytes()); err != nil || string(b) != "agent" {
		t.Errorf("gunzip: %q, %v", b, err)
	}
	if _, err := gunzip([]byte("not gzip")); err == nil {
		t.Error("gunzipped garbage")
	}
}
