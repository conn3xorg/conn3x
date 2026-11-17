// Copyright (c) The Conn3x Authors
// SPDX-License-Identifier: MPL-2.0

package provider

import (
	"context"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/opentofu/opentofu/internal/conn3x/modules/pkg"
	"github.com/opentofu/opentofu/internal/conn3x/transport/ssh"
)

// osReleaseRunner answers cat /etc/os-release and counts how often.
type osReleaseRunner struct{ reads atomic.Int32 }

func (r *osReleaseRunner) Run(_ context.Context, cmd string, _ []byte) (ssh.Result, error) {
	if strings.Contains(cmd, "/etc/os-release") {
		r.reads.Add(1)
		return ssh.Result{Stdout: []byte("ID=rocky\nID_LIKE=\"rhel centos fedora\"\n")}, nil
	}
	return ssh.Result{ExitCode: 1}, nil
}

// A host's package family is read once per connection, however many
// package steps ask.
func TestPackageFamilyReadOnce(t *testing.T) {
	r := &osReleaseRunner{}
	h := &hostConn{runner: r, rootKey: "web1"}
	for range 3 {
		f, err := h.packageFamily(context.Background())
		if err != nil || f != pkg.RPM {
			t.Fatalf("family %q, %v", f, err)
		}
	}
	if n := r.reads.Load(); n != 1 {
		t.Errorf("os-release read %d times, want 1", n)
	}
}
