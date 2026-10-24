// Copyright (c) The Conn3x Authors
// SPDX-License-Identifier: MPL-2.0

package addrs

import "testing"

func TestConn3xIsBuiltIn(t *testing.T) {
	p := ImpliedProviderForUnqualifiedType("conn3x")
	if !p.IsBuiltIn() {
		t.Fatalf("conn3x resolved to %s, want a built-in provider", p)
	}
	if got := p.String(); got != "terraform.io/builtin/conn3x" {
		t.Fatalf("conn3x resolved to %s", got)
	}
}
