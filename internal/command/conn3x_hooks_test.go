// Copyright (c) The Conn3x Authors
// SPDX-License-Identifier: MPL-2.0

package command

import (
	"testing"

	"github.com/opentofu/opentofu/internal/providers"
)

func TestInternalProvidersIncludeExtras(t *testing.T) {
	old := ExtraInternalProviders
	t.Cleanup(func() { ExtraInternalProviders = old })
	ExtraInternalProviders = map[string]providers.Factory{
		"conn3x": func() (providers.Interface, error) { return nil, nil },
	}
	got := (&Meta{}).internalProviders()
	if _, ok := got["conn3x"]; !ok {
		t.Fatal("conn3x missing from internal providers")
	}
	if _, ok := got["terraform"]; !ok {
		t.Fatal("terraform built-in provider lost")
	}
}
