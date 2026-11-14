// Copyright (c) The Conn3x Authors
// SPDX-License-Identifier: MPL-2.0

package main

import "testing"

func TestBatchSize(t *testing.T) {
	for _, c := range []struct {
		size string
		n    int
		want int
	}{{"", 7, 7}, {"", 0, 1}, {"2", 7, 2}, {"20%", 7, 2}, {"100%", 7, 7}, {"1%", 3, 1}} {
		if got := batchOf(c.size, c.n); got != c.want {
			t.Errorf("batchOf(%q, %d) = %d, want %d", c.size, c.n, got, c.want)
		}
	}
	for _, bad := range []string{"0", "-1", "x", "0%", "101%", "2.5"} {
		if checkBatchSize(bad) == nil {
			t.Errorf("%q passed", bad)
		}
	}
}
