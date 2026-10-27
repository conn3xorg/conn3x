// Copyright (c) The Conn3x Authors
// SPDX-License-Identifier: MPL-2.0

package provider

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"

	"github.com/opentofu/opentofu/internal/conn3x/modules/edit"
	"github.com/opentofu/opentofu/internal/conn3x/modules/moduletest"
)

// Edits to one file on one host take turns. Run together, each reads the
// file before the others write and the last write wins, as with a line
// step's for_each items (#139).
func TestEditsToOneFileTakeTurns(t *testing.T) {
	path := filepath.Join(t.TempDir(), "race.conf")
	const n = 12
	var wg sync.WaitGroup
	errs := make(chan error, n)
	for i := range n {
		wg.Add(1)
		go func() {
			defer wg.Done()
			h := &hostConn{runner: moduletest.Local{}, rootKey: "web1"}
			l := edit.Line{Line: fmt.Sprintf("k%d=%d", i, i)}
			errs <- editFile(context.Background(), h, path, true, func(s string) (string, error) { return edit.ApplyLine(s, l) })
		}()
	}
	wg.Wait()
	close(errs)
	for err := range errs {
		if err != nil {
			t.Fatal(err)
		}
	}
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	for i := range n {
		if want := fmt.Sprintf("k%d=%d", i, i); !strings.Contains(string(b), want+"\n") {
			t.Errorf("%s is missing %q; got:\n%s", path, want, b)
		}
	}
}
