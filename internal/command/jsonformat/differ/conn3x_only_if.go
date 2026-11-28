// Copyright (c) The Conn3x Authors
// SPDX-License-Identifier: MPL-2.0

package differ

import (
	"github.com/opentofu/opentofu/internal/command/jsonformat/structured"
	"github.com/opentofu/opentofu/internal/command/jsonprovider"
)

// conn3xUngated reports whether a Conn3x step's write-only only_if is
// left out of its diff: when skipped is null before and after, the step
// has no only_if, or runs. Every write-only attribute is otherwise listed
// on every create and update, so every step in every plan, handlers
// included, would gain an only_if line. Where only_if decides something,
// skipped is true or unknown, and the line stays.
func conn3xUngated(block *jsonprovider.Block, values structured.ChangeMap) bool {
	if a, ok := block.Attributes["skipped"]; !ok || !a.Computed {
		return false
	}
	s := values.GetChild("skipped")
	unknown, _ := s.Unknown.(bool)
	return s.Before == nil && s.After == nil && !unknown
}
