// Copyright (c) The Conn3x Authors
// SPDX-License-Identifier: MPL-2.0

package lifecycle

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/opentofu/opentofu/internal/conn3x/modules/moduletest"
)

// state "absent" waits for the path to be gone.
func TestWaitForAbsent(t *testing.T) {
	ctx := context.Background()
	p := filepath.Join(t.TempDir(), "lock")
	if err := os.WriteFile(p, nil, 0o644); err != nil {
		t.Fatal(err)
	}
	w := WaitFor{Path: p, Absent: true, Timeout: 10 * time.Second}
	if ok, err := w.Ready(ctx, moduletest.Local{}); err != nil || ok {
		t.Fatalf("the lock is there: ready %v, %v", ok, err)
	}
	go func() { time.Sleep(1500 * time.Millisecond); _ = os.Remove(p) }()
	if err := w.Wait(ctx, moduletest.Local{}); err != nil {
		t.Fatal(err)
	}
	if ok, err := w.Ready(ctx, moduletest.Local{}); err != nil || !ok {
		t.Fatalf("the lock is gone: ready %v, %v", ok, err)
	}
	if err := os.WriteFile(p, nil, 0o644); err != nil {
		t.Fatal(err)
	}
	err := WaitFor{Path: p, Absent: true, Timeout: time.Second}.Wait(ctx, moduletest.Local{})
	if err == nil || !strings.Contains(err.Error(), "to be gone") {
		t.Fatalf("timeout: %v", err)
	}
	for _, bad := range []WaitFor{{URL: URLCheck{URL: "http://h"}, Absent: true}, {Path: "/x", Contains: "a", Absent: true}} {
		if bad.Validate() == nil {
			t.Errorf("%+v accepted", bad)
		}
	}
}
