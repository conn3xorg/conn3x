// Copyright (c) The Conn3x Authors
// SPDX-License-Identifier: MPL-2.0

package lifecycle

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/opentofu/opentofu/internal/conn3x/modules/moduletest"
)

func TestWaitForValidate(t *testing.T) {
	for _, ok := range []WaitFor{{Path: "/run/app.ready"}, {Port: 8080}, {Port: 22, Timeout: time.Minute}} {
		if err := ok.Validate(); err != nil {
			t.Errorf("rejected %+v: %v", ok, err)
		}
	}
	for _, bad := range []WaitFor{{}, {Path: "/a", Port: 80}, {Path: "relative"}, {Port: 70000}, {Port: -1}} {
		if bad.Validate() == nil {
			t.Errorf("accepted %+v", bad)
		}
	}
}

func TestWaitForPath(t *testing.T) {
	ctx := context.Background()
	p := t.TempDir() + "/ready"
	w := WaitFor{Path: p, Timeout: 10 * time.Second}
	if ok, err := w.Ready(ctx, moduletest.Local{}); err != nil || ok {
		t.Fatalf("Ready before the path exists = %v, %v", ok, err)
	}
	go func() { time.Sleep(1500 * time.Millisecond); _, _ = moduletest.Local{}.Run(ctx, "touch "+p, nil) }()
	if err := w.Wait(ctx, moduletest.Local{}); err != nil {
		t.Fatal(err)
	}
	err := WaitFor{Path: p + ".never", Timeout: 2 * time.Second}.Wait(ctx, moduletest.Local{})
	if err == nil || !strings.Contains(err.Error(), "timed out after 2s") {
		t.Fatalf("err = %v", err)
	}
}
