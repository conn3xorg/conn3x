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

func TestValidateGuards(t *testing.T) {
	for _, bad := range []Guards{{Creates: "relative"}, {Removes: "x/y"}} {
		if bad.Validate() == nil {
			t.Errorf("Validate(%+v) accepted", bad)
		}
	}
}
