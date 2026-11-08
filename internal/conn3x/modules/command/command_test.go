// Copyright (c) The Conn3x Authors
// SPDX-License-Identifier: MPL-2.0

package command

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/opentofu/opentofu/internal/conn3x/modules/moduletest"
)

var ctx = context.Background()
var host = moduletest.Local{}

func TestSatisfiedCreates(t *testing.T) {
	path := filepath.Join(t.TempDir(), "marker")
	g := Guards{Creates: path}
	if ok, err := Satisfied(ctx, host, g); err != nil || ok {
		t.Fatalf("missing creates path: satisfied=%v err=%v", ok, err)
	}
	_ = os.WriteFile(path, nil, 0o644)
	if ok, _ := Satisfied(ctx, host, g); !ok {
		t.Fatal("existing creates path not satisfied")
	}
}

func TestSatisfiedRemoves(t *testing.T) {
	path := filepath.Join(t.TempDir(), "old")
	g := Guards{Removes: path}
	if ok, _ := Satisfied(ctx, host, g); !ok {
		t.Fatal("missing removes path should be satisfied")
	}
	_ = os.WriteFile(path, nil, 0o644)
	if ok, _ := Satisfied(ctx, host, g); ok {
		t.Fatal("existing removes path should need a run")
	}
}

func TestSatisfiedUnless(t *testing.T) {
	if ok, _ := Satisfied(ctx, host, Guards{Unless: "true"}); !ok {
		t.Fatal("unless that succeeds should be satisfied")
	}
	if ok, _ := Satisfied(ctx, host, Guards{Unless: "exit 1"}); ok {
		t.Fatal("unless that fails should need a run")
	}
}

func TestSatisfiedWithoutGuards(t *testing.T) {
	if ok, _ := Satisfied(ctx, host, Guards{}); ok {
		t.Fatal("no guards means nothing can be checked; report not satisfied")
	}
}

func TestRunCapturesAndTruncates(t *testing.T) {
	out, err := Run(ctx, host, "printf 'hello'; printf 'warn' >&2")
	if err != nil {
		t.Fatal(err)
	}
	if out.Stdout != "hello" || out.Stderr != "warn" || out.ExitCode != 0 {
		t.Fatalf("got %+v", out)
	}
	big, _ := Run(ctx, host, "head -c 20000 /dev/zero | tr '\\0' x")
	if len(big.Stdout) > MaxOutput+len(truncated) || !strings.HasSuffix(big.Stdout, truncated) {
		t.Fatalf("output not truncated: %d bytes", len(big.Stdout))
	}
}

func TestRunFailureIsAnError(t *testing.T) {
	_, err := Run(ctx, host, "echo broken >&2; exit 7")
	if err == nil || !strings.Contains(err.Error(), "exit status 7") || !strings.Contains(err.Error(), "broken") {
		t.Fatalf("err = %v", err)
	}
}

// A failure with nothing printed has no dangling colon, and long output is
// cut to its last lines, where the reason usually is.
func TestRunFailureMessage(t *testing.T) {
	_, err := Run(ctx, host, "exit 1")
	if err == nil || err.Error() != "command failed with exit status 1" {
		t.Fatalf("err = %q", err)
	}
	_, err = Run(ctx, host, "for i in $(seq 1 30); do echo line$i >&2; done; exit 2")
	msg := err.Error()
	if !strings.Contains(msg, "(20 earlier lines)") || !strings.Contains(msg, "line21") || !strings.HasSuffix(msg, "line30") || strings.Contains(msg, "line20\n") {
		t.Fatalf("err = %q", msg)
	}
}

func TestValidateGuards(t *testing.T) {
	for _, bad := range []Guards{{Creates: "relative"}, {Removes: "x/y"}} {
		if bad.Validate() == nil {
			t.Errorf("Validate(%+v) accepted", bad)
		}
	}
}
