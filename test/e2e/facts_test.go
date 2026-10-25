// Copyright (c) The Conn3x Authors
// SPDX-License-Identifier: MPL-2.0

//go:build e2e

package e2e

import (
	"strconv"
	"strings"
	"testing"
)

func TestHostFacts(t *testing.T) {
	families := map[string]string{"rocky10": "redhat rocky", "ubuntu2404": "debian ubuntu", "debian13": "debian debian"}
	for _, image := range linuxImages {
		t.Run(image, func(t *testing.T) {
			h := startHost(t, image)
			w := newWorkdir(t, "facts")
			w.write(circuitVars{Port: h.port, KeyFile: h.keyFile, KnownHosts: h.knownHosts})
			w.mustConn3x("init", "-no-color")
			w.mustConn3x("apply", "-auto-approve", "-no-color")

			want := families[image] + " " + strings.TrimSpace(h.exec("", "uname", "-m")) + " " + strings.TrimSpace(h.exec("", "nproc")) + "\n"
			if got := h.exec("", "cat", "/etc/conn3x-facts"); got != want {
				t.Fatalf("facts file = %q, want %q", got, want)
			}
			if mb, err := strconv.Atoi(strings.TrimSpace(w.mustConn3x("output", "-raw", "memory_mb"))); err != nil || mb < 256 {
				t.Fatalf("memory_mb = %d, %v", mb, err)
			}
			if out := w.mustConn3x("plan", "-no-color"); !strings.Contains(out, "No changes.") {
				t.Fatalf("plan after apply:\n%s", out)
			}
		})
	}
}
