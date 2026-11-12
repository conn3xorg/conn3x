// Copyright (c) The Conn3x Authors
// SPDX-License-Identifier: MPL-2.0

package provider

import (
	"context"
	"runtime"
	"testing"

	"github.com/zclconf/go-cty/cty"
)

func TestControllerRunsLocally(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("needs /bin/sh")
	}
	conn := cty.ObjectVal(map[string]cty.Value{"host": cty.StringVal("controller"), "controller": cty.True})
	h, err := pooled(context.Background(), conn, 0)
	if err != nil || h != controller() {
		t.Fatalf("pooled = %v, %v; want the controller", h, err)
	}
	res, err := h.Run(context.Background(), "read x; echo \"$x\"; echo oops >&2; exit 3", []byte("in\n"))
	if err != nil || string(res.Stdout) != "in\n" || string(res.Stderr) != "oops\n" || res.ExitCode != 3 {
		t.Errorf("got %q, %q, %d, %v", res.Stdout, res.Stderr, res.ExitCode, err)
	}
}
