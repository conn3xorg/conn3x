// Copyright (c) The Conn3x Authors
// SPDX-License-Identifier: MPL-2.0

package main

import (
	"slices"
	"testing"
)

func TestWithDefaultParallelism(t *testing.T) {
	for _, tc := range []struct {
		cmd  string
		in   []string
		want []string
	}{
		{"plan", []string{"-chdir=x", "plan", "-out=p"}, []string{"-chdir=x", "plan", "-parallelism=50", "-out=p"}},
		// The user's flag comes later, so it wins.
		{"apply", []string{"apply", "-parallelism=4"}, []string{"apply", "-parallelism=50", "-parallelism=4"}},
		{"init", []string{"init"}, []string{"init"}},
		{"state list", []string{"state", "list"}, []string{"state", "list"}},
	} {
		if got := withDefaultParallelism(tc.cmd, tc.in); !slices.Equal(got, tc.want) {
			t.Errorf("%s %q: got %q, want %q", tc.cmd, tc.in, got, tc.want)
		}
	}
}
