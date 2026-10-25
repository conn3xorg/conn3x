// Copyright (c) The Conn3x Authors
// SPDX-License-Identifier: MPL-2.0

//go:build e2e

package e2e

import (
	"strings"
	"testing"
)

// init suggests state encryption when it's off, and stays quiet when it's on.
func TestInitSuggestsStateEncryption(t *testing.T) {
	w := newWorkdir(t, "encryption")
	w.write(struct{ Encrypted bool }{false})
	if out := w.mustConn3x("init", "-no-color"); !strings.Contains(out, "state isn't encrypted") {
		t.Fatalf("init without encryption:\n%s", out)
	}
	w = newWorkdir(t, "encryption")
	w.write(struct{ Encrypted bool }{true})
	if out := w.mustConn3x("init", "-no-color"); strings.Contains(out, "state isn't encrypted") {
		t.Fatalf("init with encryption still warned:\n%s", out)
	}
}
