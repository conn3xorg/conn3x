// Copyright (c) The Conn3x Authors
// SPDX-License-Identifier: MPL-2.0

package provider

import "github.com/opentofu/opentofu/internal/configs/configschema"

func emptyBlock() *configschema.Block {
	return &configschema.Block{}
}
