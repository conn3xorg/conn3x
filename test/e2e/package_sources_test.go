// Copyright (c) The Conn3x Authors
// SPDX-License-Identifier: MPL-2.0

//go:build e2e

package e2e

import (
	"strings"
	"testing"
)

type packageSourcesVars struct{ Port, KeyFile, KnownHosts, Ext, Remove string }

// A package_sources step keeps the distribution's sources, Conn3x's and
// keep, and moves the rest aside; one added by hand is named on the next
// plan. remove takes a distribution file, but not one Conn3x wrote.
func TestPackageSources(t *testing.T) {
	// Every source here is disabled, so apt-get update and dnf still only
	// reach the distribution's mirrors.
	type layout struct{ dir, ext, distro, ours, stray string }
	apt := layout{"/etc/apt/sources.list.d", ".sources", "",
		"# Managed by Conn3x.\nTypes: deb\nURIs: http://127.0.0.1:9/ours\nSuites: x\nComponents: main\nEnabled: no\n",
		"Types: deb\nURIs: http://127.0.0.1:9/stray\nSuites: x\nComponents: main\nEnabled: no\n"}
	rpm := layout{"/etc/yum.repos.d", ".repo", "",
		"# Managed by Conn3x.\n[ours]\nbaseurl=http://127.0.0.1:9/ours\nenabled=0\n",
		"[stray]\nbaseurl=http://127.0.0.1:9/stray\nenabled=0\n"}
	distro := map[string]string{"rocky10": "rocky-devel.repo", "ubuntu2404": "ubuntu.sources", "debian13": "debian.sources"}
	for _, image := range linuxImages {
		t.Run(image, func(t *testing.T) {
			l := apt
			if rpmImage(image) {
				l = rpm
			}
			h := startHost(t, image)
			w := newWorkdir(t, "package_sources")
			vars := packageSourcesVars{Port: h.port, KeyFile: h.keyFile, KnownHosts: h.knownHosts, Ext: l.ext}
			w.writeAs("main.circuit.hcl", vars)
			w.mustConn3x("init", "-no-color")

			put := func(name, content string) { h.exec(content, "sh", "-c", "cat > "+l.dir+"/"+name) }
			put("ours"+l.ext, l.ours)
			put("kept"+l.ext, l.stray)
			put("stray"+l.ext, l.stray)
			ls := func() string {
				return h.exec("", "sh", "-c", "ls "+l.dir+"; echo --; ls /var/lib/conn3x/disabled-sources 2>/dev/null || :")
			}
			before := ls()

			w.mustConn3x("apply", "-auto-approve", "-no-color")
			after := ls()
			kept, moved, _ := strings.Cut(after, "--")
			if strings.Contains(kept, "stray"+l.ext) || !strings.Contains(moved, "stray"+l.ext) || !strings.Contains(kept, "ours"+l.ext) || !strings.Contains(kept, "kept"+l.ext) {
				t.Fatalf("before:\n%s\nafter:\n%s", before, after)
			}
			if d := distro[image]; d != "" && !strings.Contains(kept, d) {
				t.Fatalf("the distribution's %s was moved:\n%s", d, after)
			}
			if out := w.mustConn3x("plan", "-no-color"); !strings.Contains(out, "No changes.") {
				t.Fatalf("plan after apply:\n%s", out)
			}

			// A source added by hand is named on the next plan, and moved;
			// the one moved before is kept as a numbered backup.
			put("stray"+l.ext, l.stray)
			out := w.mustConn3x("plan", "-no-color")
			if !strings.Contains(out, "stray"+l.ext) || strings.Contains(out, "127.0.0.1:9") || !strings.Contains(out, "1 to change") {
				t.Fatalf("plan with a source added by hand:\n%s", out)
			}
			w.mustConn3x("apply", "-auto-approve", "-no-color")
			if got := ls(); !strings.Contains(got, "stray"+l.ext+".~1~") {
				t.Fatalf("no numbered backup:\n%s", got)
			}

			// remove takes the distribution's file...
			if d := distro[image]; d != "" {
				vars.Remove = `"` + d + `"`
				w.writeAs("main.circuit.hcl", vars)
				w.mustConn3x("apply", "-auto-approve", "-no-color")
				if kept, _, _ := strings.Cut(ls(), "--"); strings.Contains(kept, d) {
					t.Fatalf("remove left %s:\n%s", d, kept)
				}
			}
			// ...but not one a repository step wrote.
			vars.Remove = `"ours` + l.ext + `"`
			w.writeAs("main.circuit.hcl", vars)
			if out, code := w.conn3x("apply", "-auto-approve", "-no-color"); code == 0 || !strings.Contains(out, "which a repository step wrote") {
				t.Fatalf("remove naming a repository step's file (exit %d):\n%s", code, out)
			}
		})
	}
}
