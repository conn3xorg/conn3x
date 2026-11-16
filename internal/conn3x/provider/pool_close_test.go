// Copyright (c) The Conn3x Authors
// SPDX-License-Identifier: MPL-2.0

package provider

import (
	"context"
	"fmt"
	"os/exec"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/zclconf/go-cty/cty"
)

// ClosePool closes every pooled connection and empties the pool, so a
// later dial starts afresh.
func TestClosePool(t *testing.T) {
	f := newFileTest(t)
	h, err := pooled(context.Background(), f.conn, 0)
	if err != nil {
		t.Fatal(err)
	}
	if !h.client.Alive() {
		t.Fatal("the new connection isn't alive")
	}
	ClosePool()
	if h.client.Alive() {
		t.Error("the connection is still alive after ClosePool")
	}
	pool.Lock()
	n := len(pool.conns)
	pool.Unlock()
	if n != 0 {
		t.Errorf("%d connections left in the pool", n)
	}
	again, err := pooled(context.Background(), f.conn, 0)
	if err != nil || again == h || !again.client.Alive() {
		t.Errorf("dial after ClosePool: %v, same=%v", err, again == h)
	}
	ClosePool()
}

// ClosePool, as Conn3x exits, also ends a proxy_command dial still in
// flight: its connection never reached the pool, and DialWait would retry
// it and start another proxy.
func TestClosePoolStopsADialInFlight(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("uses sh")
	}
	nc, err := exec.LookPath("nc")
	if err != nil {
		t.Skip("needs nc for the proxy")
	}
	f := newFileTest(t)
	vals := f.conn.AsValueMap()
	marker := fmt.Sprintf("conn3x-closepool-%d", time.Now().UnixNano())
	// The proxy waits a second before it connects, so the dial is still in
	// flight when ClosePool runs. The marker names it for pgrep.
	vals["proxy_command"] = cty.ListVal([]cty.Value{cty.StringVal("sh"), cty.StringVal("-c"),
		cty.StringVal(": " + marker + "; sleep 1; exec " + nc + " %h %p")})
	conn := cty.ObjectVal(vals)
	done := make(chan *hostConn, 1)
	go func() {
		h, _ := pooled(context.Background(), conn, 0)
		done <- h
	}()
	time.Sleep(300 * time.Millisecond)
	ClosePool()
	if h := <-done; h != nil && h.client.Alive() {
		_ = h.client.Close()
		t.Error("the dial in flight still connected after ClosePool")
	}
	time.Sleep(1500 * time.Millisecond) // past the proxy's sleep, and a retry's start
	if out, _ := exec.Command("pgrep", "-f", marker).Output(); strings.TrimSpace(string(out)) != "" {
		_ = exec.Command("pkill", "-f", marker).Run()
		t.Errorf("a proxy is still running after ClosePool: pids %s", strings.Fields(string(out)))
	}
}
