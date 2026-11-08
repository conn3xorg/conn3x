// Copyright (c) The Conn3x Authors
// SPDX-License-Identifier: MPL-2.0

//go:build e2e

package e2e

import (
	"strings"
	"testing"
)

type runOnceVars struct {
	Ports           map[string]string
	Key, KnownHosts string
}

// A run_once step runs on one host, and even under per_host it's a sync
// point: the migration on db1 waits for web2's slow deploy, and the step
// after it waits for the migration on web1 and web2 too.
func TestStepRunOnce(t *testing.T) {
	db1, web1, web2 := startHost(t, "rocky10"), startHost(t, "rocky10"), startHost(t, "rocky10")
	known := shareKey(t, db1, web1, web2)

	w := newWorkdir(t, "run_once")
	w.writeAs("main.circuit.hcl", runOnceVars{
		Ports: map[string]string{"db1": db1.port, "web1": web1.port, "web2": web2.port},
		Key:   db1.keyFile, KnownHosts: known,
	})
	w.mustConn3x("init", "-no-color")
	out := w.mustConn3x("apply", "-auto-approve", "-no-color")
	t.Logf("apply:\n%s", out)
	if strings.Count(out, "conn3x_command.app__migrate[") == 0 || strings.Contains(out, `app__migrate["web1"]`) || strings.Contains(out, `app__migrate["web2"]`) {
		t.Fatalf("migrate should run on db1 only:\n%s", out)
	}
	if got := web1.exec("", "sh", "-c", "test -e /tmp/migrated && echo yes || echo no"); got != "no\n" {
		t.Error("migrate ran on web1")
	}
	migrated := stamp(t, db1.exec("", "cat", "/tmp/migrated"))
	if code := stamp(t, web2.exec("", "cat", "/tmp/code")); migrated < code {
		t.Errorf("migrate finished %.1fs before web2's deploy did", code-migrated)
	}
	for name, h := range map[string]*host{"db1": db1, "web1": web1, "web2": web2} {
		if after := stamp(t, h.exec("", "cat", "/tmp/after")); after < migrated {
			t.Errorf("%s ran the next step %.1fs before the migration finished", name, migrated-after)
		}
	}
	if out := w.mustConn3x("plan", "-no-color"); !strings.Contains(out, "No changes.") {
		t.Fatalf("plan after apply:\n%s", out)
	}
}
