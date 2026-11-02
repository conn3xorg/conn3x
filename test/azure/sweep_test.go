// Copyright (c) The Conn3x Authors
// SPDX-License-Identifier: MPL-2.0

package azure

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// sweep runs sweep.sh against a fake az that lists groups and records deletes.
func sweep(t *testing.T, listing string, env []string, args ...string) (deleted []string, out string, err error) {
	t.Helper()
	dir := t.TempDir()
	log := filepath.Join(dir, "deleted")
	list := filepath.Join(dir, "listing")
	if err := os.WriteFile(list, []byte(listing), 0o644); err != nil {
		t.Fatal(err)
	}
	fake := "#!/bin/sh\ncase \"$1 $2\" in\n\"group list\") cat " + list + " ;;\n\"group delete\") echo \"$4\" >> " + log + " ;;\n*) exit 9 ;;\nesac\n"
	if err := os.WriteFile(filepath.Join(dir, "az"), []byte(fake), 0o755); err != nil {
		t.Fatal(err)
	}
	cmd := exec.Command("bash", append([]string{"sweep.sh"}, args...)...)
	cmd.Env = append(append(os.Environ(), "PATH="+dir+":"+os.Getenv("PATH")), env...)
	b, err := cmd.CombinedOutput()
	got, _ := os.ReadFile(log)
	return strings.Fields(string(got)), string(b), err
}

func TestSweepDeletesOnlyOwnOldTaggedGroups(t *testing.T) {
	old := time.Now().UTC().Add(-5 * time.Hour).Format("2006-01-02T15:04:05Z")
	fresh := time.Now().UTC().Add(-time.Hour).Format("2006-01-02T15:04:05Z")
	listing := strings.Join([]string{
		"conn3x-ci-old\ttrue\t" + old,
		"conn3x-ci-fresh\ttrue\t" + fresh,
		"conn3x-ci-untagged\tNone\t" + old,
		"conn3x-ci-tag-false\tfalse\t" + old,
		"conn3x-ci-bad-time\ttrue\tyesterday",
		"conn3x-ci-no-time\ttrue\tNone",
		"NetworkWatcherRG\ttrue\t" + old,
		"production\ttrue\t" + old,
		"my-conn3x-ci-thing\ttrue\t" + old,
		"sentrello-prod\tNone\tNone",
	}, "\n") + "\n"
	deleted, out, err := sweep(t, listing, nil)
	if err != nil {
		t.Fatalf("%v\n%s", err, out)
	}
	if strings.Join(deleted, " ") != "conn3x-ci-old" {
		t.Errorf("deleted %v\n%s", deleted, out)
	}
	if deleted, out, err = sweep(t, listing, nil, "-n"); err != nil || len(deleted) != 0 || !strings.Contains(out, "would delete conn3x-ci-old") {
		t.Errorf("dry run deleted %v, %v\n%s", deleted, err, out)
	}
	if deleted, _, _ = sweep(t, listing, []string{"SWEEP_PREFIX=conn3x-ci-other-"}); len(deleted) != 0 {
		t.Errorf("a narrower prefix deleted %v", deleted)
	}
	if deleted, _, err = sweep(t, listing, []string{"SWEEP_PREFIX=production"}); err == nil || len(deleted) != 0 {
		t.Errorf("a prefix outside ours ran: %v, %v", deleted, err)
	}
	if deleted, _, err = sweep(t, listing, []string{"SWEEP_PREFIX="}); len(deleted) > 1 {
		t.Errorf("an empty prefix widened it: %v, %v", deleted, err)
	}
	if _, _, err = sweep(t, listing, nil, "soon"); err == nil {
		t.Error("a bad age ran")
	}
}
