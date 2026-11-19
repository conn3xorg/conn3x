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

// contains waits for the file to exist and match, with ^ at each line.
func TestWaitForContains(t *testing.T) {
	ctx := context.Background()
	p := filepath.Join(t.TempDir(), "app.log")
	w := WaitFor{Path: p, Contains: "^Started", Timeout: 10 * time.Second}
	if ok, err := w.Ready(ctx, moduletest.Local{}); err != nil || ok {
		t.Fatalf("no file: ready %v, %v", ok, err)
	}
	if err := os.WriteFile(p, []byte("booting\nnot Started\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if ok, err := w.Ready(ctx, moduletest.Local{}); err != nil || ok {
		t.Fatalf("no line starts with it: ready %v, %v", ok, err)
	}
	go func() {
		time.Sleep(1500 * time.Millisecond)
		f, _ := os.OpenFile(p, os.O_APPEND|os.O_WRONLY, 0)
		_, _ = f.WriteString("Started in 2s\n")
		_ = f.Close()
	}()
	if err := w.Wait(ctx, moduletest.Local{}); err != nil {
		t.Fatal(err)
	}
	err := WaitFor{Path: p, Contains: "never", Timeout: time.Second}.Wait(ctx, moduletest.Local{})
	if err == nil || !strings.Contains(err.Error(), "to match") {
		t.Fatalf("timeout: %v", err)
	}
}

func TestWaitForContainsValidate(t *testing.T) {
	for _, c := range []struct {
		w    WaitFor
		want string
	}{
		{WaitFor{Port: 80, Contains: "x"}, "contains is for path"},
		{WaitFor{URL: URLCheck{URL: "http://h"}, Contains: "x"}, "contains is for path"},
		{WaitFor{Path: "/x", Contains: "("}, "isn't a regular expression"},
	} {
		if err := c.w.Validate(); err == nil || !strings.Contains(err.Error(), c.want) {
			t.Errorf("%+v: %v, want %q", c.w, err, c.want)
		}
	}
	if err := (WaitFor{Path: "/x", Contains: "ok"}).Validate(); err != nil {
		t.Error(err)
	}
}
