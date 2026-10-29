// Copyright (c) The Conn3x Authors
// SPDX-License-Identifier: MPL-2.0

package provider

import (
	"context"
	"testing"
	"time"
)

// OpenTofu asks providers to stop through Stop, not by cancelling the
// context it passes to apply, so Stop must end SSH work already running.
func TestStopCancelsWorkInFlight(t *testing.T) {
	pi, _ := New()
	p := pi.(*Provider)
	ctx, done := p.withStop(context.Background())
	defer done()
	if err := p.Stop(context.Background()); err != nil {
		t.Fatal(err)
	}
	select {
	case <-ctx.Done():
	case <-time.After(time.Second):
		t.Fatal("Stop didn't cancel the context of work in flight")
	}
}
