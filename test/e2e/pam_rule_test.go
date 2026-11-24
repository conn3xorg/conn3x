// Copyright (c) The Conn3x Authors
// SPDX-License-Identifier: MPL-2.0

//go:build e2e

package e2e

import (
	"strings"
	"testing"
)

type pamVars struct {
	Port, KeyFile, KnownHosts         string
	Service, Unix, UnixControl        string
	Faillock, Debug, NoNullok, Select bool
}

// pam_rule adds pam_faillock before pam_unix in Ubuntu's common-auth and
// in a Rocky Linux service file authselect doesn't own, plans clean, puts
// a rule taken out by hand back, adds and takes out arguments, and takes
// its rules out again when the steps go. On Rocky it refuses system-auth,
// which authselect owns.
func TestPAMRule(t *testing.T) {
	for _, c := range []struct{ image, service, control string }{
		{"ubuntu2404", "common-auth", "[success=1 default=ignore]"},
		{"rocky10", "c3x-demo", "sufficient"},
	} {
		t.Run(c.image, func(t *testing.T) {
			h := startHost(t, c.image)
			file := "/etc/pam.d/" + c.service
			if c.image == "rocky10" {
				h.exec("", "cp", "/etc/authselect/system-auth", file)
			}
			read := func() string { return h.exec("", "cat", file) }
			owner := func() string { return h.exec("", "stat", "-c", "%a %U %G", file) }
			orig, origOwner := read(), owner()
			var unixLine string
			for _, l := range strings.Split(orig, "\n") {
				if strings.HasPrefix(l, "auth") && strings.Contains(l, "pam_unix.so") {
					unixLine = l
				}
			}
			if !strings.HasSuffix(unixLine, " nullok") {
				t.Fatalf("no pam_unix line ending in nullok in %s:\n%s", file, orig)
			}

			vars := pamVars{Port: h.port, KeyFile: h.keyFile, KnownHosts: h.knownHosts, Service: c.service,
				Unix: "auth " + c.control + " pam_unix.so", UnixControl: c.control, Faillock: true}
			w := newWorkdir(t, "pam_rule")
			w.writeAs("main.circuit.hcl", vars)
			w.mustConn3x("init", "-no-color")
			w.mustConn3x("apply", "-auto-approve", "-no-color")
			got := read()
			if !strings.Contains(got, "pam_faillock.so preauth\n"+unixLine+"\n") || strings.Count(got, "\n") != strings.Count(orig, "\n")+1 {
				t.Fatalf("faillock isn't just before pam_unix:\n%s", got)
			}
			if o := owner(); o != origOwner {
				t.Fatalf("mode and owner went from %q to %q", origOwner, o)
			}
			if out := w.mustConn3x("plan", "-no-color"); !strings.Contains(out, "No changes.") {
				t.Fatalf("plan after apply:\n%s", out)
			}

			h.exec("", "sed", "-i", "/pam_faillock/d", file)
			if out := w.mustConn3x("plan", "-no-color"); !strings.Contains(out, "1 to change") {
				t.Fatalf("plan after taking faillock out by hand:\n%s", out)
			}
			w.mustConn3x("apply", "-auto-approve", "-no-color")
			if read() != got {
				t.Fatalf("apply didn't put faillock back:\n%s", read())
			}

			vars.Debug = true
			w.writeAs("main.circuit.hcl", vars)
			w.mustConn3x("apply", "-auto-approve", "-no-color")
			if !strings.Contains(read(), unixLine+" debug\n") {
				t.Fatalf("args_present didn't add debug:\n%s", read())
			}
			vars.NoNullok = true
			w.writeAs("main.circuit.hcl", vars)
			w.mustConn3x("apply", "-auto-approve", "-no-color")
			bare := strings.TrimSuffix(unixLine, " nullok")
			if !strings.Contains(read(), bare+" debug\n") {
				t.Fatalf("args_absent didn't take nullok out:\n%s", read())
			}
			if out := w.mustConn3x("plan", "-no-color"); !strings.Contains(out, "No changes.") {
				t.Fatalf("plan with three steps on one file:\n%s", out)
			}

			// on_remove = "delete" takes out the rule and the argument the
			// steps added; no_nullok's change stays.
			vars.Faillock, vars.Debug = false, false
			w.writeAs("main.circuit.hcl", vars)
			w.mustConn3x("apply", "-auto-approve", "-no-color")
			if want := strings.Replace(orig, unixLine, bare, 1); read() != want {
				t.Fatalf("after removing the steps:\n%s\nwant:\n%s", read(), want)
			}

			if c.image != "rocky10" {
				return
			}
			before := h.exec("", "cat", "/etc/authselect/system-auth")
			vars.Select = true
			w.writeAs("main.circuit.hcl", vars)
			out, code := w.conn3x("apply", "-auto-approve", "-no-color")
			if code == 0 || !strings.Contains(out, "managed by authselect") || !strings.Contains(out, "authselect enable-feature with-faillock") {
				t.Fatalf("apply on system-auth: exit %d\n%s", code, out)
			}
			if after := h.exec("", "cat", "/etc/authselect/system-auth"); after != before {
				t.Fatalf("system-auth changed:\n%s", after)
			}
		})
	}
}
