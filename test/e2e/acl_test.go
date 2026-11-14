// Copyright (c) The Conn3x Authors
// SPDX-License-Identifier: MPL-2.0

//go:build e2e

package e2e

import (
	"strings"
	"testing"
)

type aclVars struct {
	Port, KeyFile, KnownHosts, State string
	Pkg                              bool
}

// acl keeps one ACL entry: it names the package when setfacl is missing,
// puts back a change by hand, takes an entry out with state = "absent",
// and takes the default entry out when the step goes.
func TestACL(t *testing.T) {
	for _, image := range linuxImages {
		t.Run(image, func(t *testing.T) {
			h := startHost(t, image)
			facl := func() string { return h.exec("", "sh", "-c", "getfacl --omit-header --absolute-names /srv/data 2>&1; true") }
			w := newWorkdir(t, "acl")
			vars := aclVars{Port: h.port, KeyFile: h.keyFile, KnownHosts: h.knownHosts, State: "present"}
			w.writeAs("main.circuit.hcl", vars)
			w.mustConn3x("init", "-no-color")
			if out, code := w.conn3x("apply", "-auto-approve", "-no-color"); code == 0 || !strings.Contains(out, "install the acl package") {
				t.Fatalf("without setfacl (exit %d):\n%s", code, out)
			}
			vars.Pkg = true
			w.writeAs("main.circuit.hcl", vars)
			w.mustConn3x("apply", "-auto-approve", "-no-color")
			if got := facl(); !strings.Contains(got, "\nuser:daemon:r-x") || !strings.Contains(got, "default:user:daemon:r--") {
				t.Fatalf("after apply:\n%s", got)
			}
			if out := w.mustConn3x("plan", "-no-color"); !strings.Contains(out, "No changes.") {
				t.Fatalf("plan after apply:\n%s", out)
			}

			// setfacl raises the mask with the entry, and the mask is what the
			// mode's group digit shows, so the directory step sees it too.
			h.exec("", "setfacl", "-m", "u:daemon:rwx", "/srv/data")
			if out := w.mustConn3x("plan", "-no-color"); !strings.Contains(out, "2 to change") || !strings.Contains(out, `"0770" -> "0750"`) {
				t.Fatalf("plan after a change by hand:\n%s", out)
			}
			w.mustConn3x("apply", "-auto-approve", "-no-color")
			if got := facl(); !strings.Contains(got, "\nuser:daemon:r-x") {
				t.Fatalf("apply didn't put it back:\n%s", got)
			}

			vars.State = "absent"
			w.writeAs("main.circuit.hcl", vars)
			w.mustConn3x("apply", "-auto-approve", "-no-color")
			if got := facl(); strings.Contains(got, "\nuser:daemon:") || !strings.Contains(got, "default:user:daemon:r--") {
				t.Fatalf(`with state = "absent":`+"\n%s", got)
			}

			w.mustConn3x("destroy", "-auto-approve", "-no-color")
			if got := facl(); strings.Contains(got, "default:user:daemon") {
				t.Fatalf("on_remove = \"delete\" left the default entry:\n%s", got)
			}
		})
	}
}
