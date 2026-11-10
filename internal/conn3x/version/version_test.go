// Copyright (c) The Conn3x Authors
// SPDX-License-Identifier: MPL-2.0

package version

import (
	"os"
	"strings"
	"testing"
)

func TestString(t *testing.T) {
	old := Version
	t.Cleanup(func() { Version = old })
	Version = "1.2.3"

	// The upstream sync rewrites UPSTREAM, so the test reads it too.
	upstream, err := os.ReadFile("UPSTREAM")
	if err != nil {
		t.Fatal(err)
	}
	want := "Conn3x v1.2.3 (built on OpenTofu " + strings.TrimSpace(string(upstream)) + ")"
	if got := String(); got != want {
		t.Fatalf("String() = %q, want %q", got, want)
	}
}
