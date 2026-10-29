// Copyright (c) The Conn3x Authors
// SPDX-License-Identifier: MPL-2.0

package provider

import (
	"sync"
	"testing"

	"github.com/zclconf/go-cty/cty"
)

func TestDialReusesOneConnectionPerHost(t *testing.T) {
	f := newFileTest(t)
	var wg sync.WaitGroup
	for i := 0; i < 8; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			h, err := dialConnection(ctx, f.conn)
			if err != nil {
				t.Error(err)
				return
			}
			if _, err := h.Run(ctx, "true", nil); err != nil {
				t.Error(err)
			}
		}()
	}
	wg.Wait()
	if got := f.server.Accepts(); got != 1 {
		t.Fatalf("server accepted %d connections, want 1", got)
	}
}

func TestDialSeparatesDifferentLogins(t *testing.T) {
	f := newFileTest(t)
	if _, err := dialConnection(ctx, f.conn); err != nil {
		t.Fatal(err)
	}
	vals := f.conn.AsValueMap()
	vals["user"] = cty.StringVal("someone-else")
	if _, err := dialConnection(ctx, cty.ObjectVal(vals)); err != nil {
		t.Fatal(err)
	}
	if got := f.server.Accepts(); got != 2 {
		t.Fatalf("server accepted %d connections, want 2 for two logins", got)
	}
}

func TestDialReconnectsAfterTheConnectionDrops(t *testing.T) {
	f := newFileTest(t)
	h, err := dialConnection(ctx, f.conn)
	if err != nil {
		t.Fatal(err)
	}
	h.client.Close() // the connection dies, as if the host rebooted
	h2, err := dialConnection(ctx, f.conn)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := h2.Run(ctx, "true", nil); err != nil {
		t.Fatalf("pooled connection not replaced after it died: %v", err)
	}
}
