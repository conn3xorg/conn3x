// Copyright (c) The Conn3x Authors
// SPDX-License-Identifier: MPL-2.0

package provider

import (
	"context"
	"testing"
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
