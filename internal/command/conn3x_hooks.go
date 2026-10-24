// Copyright (c) The Conn3x Authors
// SPDX-License-Identifier: MPL-2.0

package command

import "github.com/opentofu/opentofu/internal/providers"

// ExtraInternalProviders are built-in providers registered by the conn3x
// binary on top of OpenTofu's own. The tofu binary leaves this empty.
var ExtraInternalProviders = map[string]providers.Factory{}
