// Copyright (c) The Conn3x Authors
// SPDX-License-Identifier: MPL-2.0

package tofu

import (
	"github.com/zclconf/go-cty/cty"

	"github.com/opentofu/opentofu/internal/lang/marks"
)

// conn3xDerivedMarks marks a file step's sha256 sensitive when its content
// is. The provider computes sha256 from content but never sees the mark, and
// an unsalted hash printed in full gives a weak secret away to a dictionary.
// Apply and refresh carry the mark on from the plan and from state.
func conn3xDerivedMarks(typeName string, pvm []cty.PathValueMarks) []cty.PathValueMarks {
	if typeName != "conn3x_file" && typeName != "conn3x_windows_file" {
		return pvm
	}
	content := cty.GetAttrPath("content")
	for _, m := range pvm {
		if m.Path.Equals(content) && m.Marks.Has(marks.Sensitive) {
			return combinePathValueMarks(pvm, []cty.PathValueMarks{{Path: cty.GetAttrPath("sha256"), Marks: cty.NewValueMarks(marks.Sensitive)}})
		}
	}
	return pvm
}
