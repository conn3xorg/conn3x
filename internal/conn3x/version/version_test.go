// Copyright (c) The Conn3x Authors
// SPDX-License-Identifier: MPL-2.0

package version

import "testing"

func TestString(t *testing.T) {
	old := Version
	t.Cleanup(func() { Version = old })
	Version = "1.2.3"

	want := "Conn3x v1.2.3 (built on OpenTofu v1.13.2)"
	if got := String(); got != want {
		t.Fatalf("String() = %q, want %q", got, want)
	}
}
