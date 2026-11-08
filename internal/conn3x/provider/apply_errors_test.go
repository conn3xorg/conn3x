// Copyright (c) The Conn3x Authors
// SPDX-License-Identifier: MPL-2.0

package provider

import (
	"errors"
	"testing"

	"github.com/zclconf/go-cty/cty"

	"github.com/opentofu/opentofu/internal/tfdiags"
)

// An apply error with no place in the configuration is pointed at the
// argument that names the step's object, so OpenTofu can say which step and
// host failed. Warnings and errors that already have a place are left alone.
func TestLocateApplyErrors(t *testing.T) {
	var diags tfdiags.Diagnostics
	diags = diags.Append(errors.New("command failed with exit status 1"))
	diags = diags.Append(attrError("creates", "bad path"))
	diags = diags.Append(tfdiags.Sourceless(tfdiags.Warning, "careful", ""))

	got := locateApplyErrors(commandSchema().Block, diags)
	if p := tfdiags.GetAttribute(got[0]); !p.Equals(cty.GetAttrPath("command")) {
		t.Errorf("bare error path = %#v, want command", p)
	}
	if got[0].Description().Summary != "command failed with exit status 1" {
		t.Errorf("summary = %q", got[0].Description().Summary)
	}
	if p := tfdiags.GetAttribute(got[1]); !p.Equals(cty.GetAttrPath("creates")) {
		t.Errorf("an error that had a place was moved to %#v", p)
	}
	if tfdiags.GetAttribute(got[2]) != nil || got[2].Severity() != tfdiags.Warning {
		t.Error("a warning was changed")
	}
	if p := tfdiags.GetAttribute(locateApplyErrors(fileSchema().Block, diags[:1])[0]); !p.Equals(cty.GetAttrPath("path")) {
		t.Errorf("file error path = %#v, want path", p)
	}
}
