// Copyright (c) The Conn3x Authors
// SPDX-License-Identifier: MPL-2.0

package main

import (
	"context"
	"testing"

	"github.com/opentofu/opentofu/internal/command"
)

func TestConn3xProviderRegistered(t *testing.T) {
	factory, ok := command.ExtraInternalProviders["conn3x"]
	if !ok {
		t.Fatal("conn3x provider not registered")
	}
	p, err := factory()
	if err != nil || p == nil {
		t.Fatalf("factory returned %v, %v", p, err)
	}
	if resp := p.GetProviderSchema(context.Background()); resp.Diagnostics.HasErrors() {
		t.Fatalf("schema errors: %s", resp.Diagnostics.Err())
	}
}
