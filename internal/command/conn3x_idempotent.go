// Copyright (c) The Conn3x Authors
// SPDX-License-Identifier: MPL-2.0

package command

import (
	"context"
	"fmt"
	"sort"
	"strings"

	"github.com/hashicorp/hcl/v2"

	"github.com/opentofu/opentofu/internal/configs"
	"github.com/opentofu/opentofu/internal/moduletest"
	"github.com/opentofu/opentofu/internal/plans"
	"github.com/opentofu/opentofu/internal/states"
)

// checkIdempotent plans again against the state the apply left, and fails
// the run when that plan would change anything.
func (runner *TestFileRunner) checkIdempotent(ctx context.Context, config *configs.Config, state *states.State, run *moduletest.Run, file *moduletest.File) {
	_, plan, diags := runner.plan(ctx, config, state, run, file)
	run.Diagnostics = run.Diagnostics.Append(diags)
	if diags.HasErrors() {
		run.Status = run.Status.Merge(moduletest.Error)
		return
	}
	var changed []string
	for _, change := range plan.Changes.Resources {
		if change.Action != plans.NoOp {
			changed = append(changed, fmt.Sprintf("%s would be %s", change.Addr, actionWord(change.Action)))
		}
	}
	if len(changed) == 0 {
		return
	}
	sort.Strings(changed)
	run.Status = run.Status.Merge(moduletest.Fail)
	run.Diagnostics = run.Diagnostics.Append(&hcl.Diagnostic{
		Severity: hcl.DiagError,
		Summary:  "Not idempotent",
		Detail:   fmt.Sprintf("The plan after the apply isn't empty:\n  - %s", strings.Join(changed, "\n  - ")),
		Subject:  run.Config.DeclRange.Ptr(),
	})
}

// actionWord is a planned action as a plan describes it.
func actionWord(a plans.Action) string {
	switch a {
	case plans.Create:
		return "created"
	case plans.Update:
		return "updated in-place"
	case plans.Delete:
		return "destroyed"
	case plans.Read:
		return "read"
	case plans.Forget:
		return "forgotten"
	}
	return "replaced"
}
