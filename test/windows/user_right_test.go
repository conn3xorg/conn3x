// Copyright (c) The Conn3x Authors
// SPDX-License-Identifier: MPL-2.0

//go:build windowshost

package windowshost

import (
	"context"
	"slices"
	"strings"
	"testing"

	"github.com/opentofu/opentofu/internal/conn3x/modules/windows"
)

// A local group made for the test is granted SeServiceLogonRight, has it
// taken by hand and given back, and loses it when the step goes with
// on_remove = "delete". The right is taken from the group however the test
// ends, before the group is deleted, so no orphaned SID is left in it.
func TestUserRightFlow(t *testing.T) {
	f := newFlow(t)
	c := connect(t)
	ctx := context.Background()
	group := accountName(t, c, "c3r")
	run(t, c, `param($A) $null = New-LocalGroup -Name $A.n`, map[string]any{"n": group})
	sid := strings.TrimSpace(run(t, c, `param($A) (Get-LocalGroup -Name $A.n).SID.Value`, map[string]any{"n": group}).Text)
	right := windows.UserRight{Name: "SeServiceLogonRight", Principals: []string{sid}}
	holds := func() bool {
		t.Helper()
		a, err := windows.ReadUserRight(ctx, c, right)
		if err != nil {
			t.Fatal(err)
		}
		return slices.ContainsFunc(a.Holders, func(s string) bool { return strings.EqualFold(s, sid) })
	}
	t.Cleanup(func() {
		if err := windows.ApplyUserRightRemove(context.Background(), c, right.Name, []string{sid}); err != nil {
			t.Errorf("taking the right back: %v", err)
		}
	})

	f.cycle(`step "logon" {
    windows_user_right {
      name       = "SeServiceLogonRight"
      principals = [".\\`+group+`"]
      on_remove  = "delete"
    }
  }`, func() {
		if err := windows.ApplyUserRightChange(ctx, c, right.Name, nil, nil, []string{sid}); err != nil {
			t.Fatal(err)
		}
	})
	if !holds() {
		t.Fatal("the group doesn't hold the right after the last apply")
	}

	f.write(``)
	f.expect(0, "apply", "-auto-approve")
	if holds() {
		t.Error(`the group still holds the right after its step went with on_remove = "delete"`)
	}
}

// Taking SeNetworkLogonRight from everyone but a new group would leave the
// login without it, so apply refuses and the right is as it was. A right
// Windows doesn't have is an error naming it.
func TestUserRightRefusals(t *testing.T) {
	f := newFlow(t)
	c := connect(t)
	ctx := context.Background()
	group := accountName(t, c, "c3r")
	run(t, c, `param($A) $null = New-LocalGroup -Name $A.n`, map[string]any{"n": group})
	before, err := windows.ReadUserRight(ctx, c, windows.UserRight{Name: "SeNetworkLogonRight"})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		sid := strings.TrimSpace(run(t, c, `param($A) (Get-LocalGroup -Name $A.n -ErrorAction SilentlyContinue).SID.Value`, map[string]any{"n": group}).Text)
		if sid != "" {
			_ = windows.ApplyUserRightRemove(context.Background(), c, "SeNetworkLogonRight", []string{sid})
		}
	})

	f.write(`step "lockout" {
    windows_user_right {
      name          = "SeNetworkLogonRight"
      principals    = [".\\` + group + `"]
      authoritative = true
    }
  }`)
	f.expect(0, "init")
	if out := f.expect(1, "apply", "-auto-approve"); !strings.Contains(out, "could lock Conn3x out") {
		t.Errorf("taking the network logon right from the login:\n%s", out)
	}
	after, err := windows.ReadUserRight(ctx, c, windows.UserRight{Name: "SeNetworkLogonRight"})
	if err != nil {
		t.Fatal(err)
	}
	slices.Sort(before.Holders)
	slices.Sort(after.Holders)
	if !slices.Equal(before.Holders, after.Holders) {
		t.Errorf("SeNetworkLogonRight holders went from %v to %v", before.Holders, after.Holders)
	}

	f.write(`step "nonesuch" {
    windows_user_right {
      name       = "SeNoSuchLogonRight"
      principals = ["Administrators"]
    }
  }`)
	if out := f.expect(1, "apply", "-auto-approve"); !strings.Contains(out, "no user right named SeNoSuchLogonRight") {
		t.Errorf("a right Windows doesn't have:\n%s", out)
	}
}

// Windows PowerShell 5.1 compiles the read's LSA type with csc.exe. What it
// leaves in the login's temp folder is logged, for the page to say.
func TestUserRightReadTempFiles(t *testing.T) {
	c := connect(t)
	ctx := context.Background()
	list := `Get-ChildItem -LiteralPath $env:TEMP -Force -ErrorAction SilentlyContinue | ForEach-Object { $_.Name }`
	before := strings.Split(strings.TrimSpace(run(t, c, list, nil).Text), "\n")
	for range 3 {
		if _, err := windows.ReadUserRight(ctx, c, windows.UserRight{Name: "SeServiceLogonRight"}); err != nil {
			t.Fatal(err)
		}
	}
	var left []string
	for _, n := range strings.Split(strings.TrimSpace(run(t, c, list, nil).Text), "\n") {
		if !slices.Contains(before, n) {
			left = append(left, strings.TrimSpace(n))
		}
	}
	t.Logf("left in %%TEMP%% after three reads: %d %v", len(left), left)
}
