// Copyright (c) The Conn3x Authors
// SPDX-License-Identifier: MPL-2.0

//go:build e2e

package e2e

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

type debconfVars struct{ Port, KeyFile, KnownHosts, Mailer string }

// TestDebconfPresetsAnswers records a select answer and a write-only
// password, sees both as in sync, changes them, and puts them back after a
// change on the host. The password never reaches state.
func TestDebconfPresetsAnswers(t *testing.T) {
	for _, image := range []string{"debian13", "ubuntu2404"} {
		t.Run(image, func(t *testing.T) {
			h := startHost(t, image)
			w := newWorkdir(t, "debconf")
			w.writeAs("main.circuit.hcl", debconfVars{h.port, h.keyFile, h.knownHosts, "Internet Site"})
			w.env = append(w.env, "TF_VAR_db_password=Pr3seed-S3cret")
			w.mustConn3x("init", "-no-color")
			w.mustConn3x("apply", "-auto-approve", "-no-color")

			password := func() string {
				return strings.TrimSpace(h.exec("GET app/db_password\n", "sh", "-c", "DEBIAN_FRONTEND=noninteractive debconf-communicate"))
			}
			if got := h.exec("", "debconf-show", "postfix"); !strings.Contains(got, "* postfix/main_mailer_type: Internet Site\n") {
				t.Fatalf("debconf-show postfix:\n%s", got)
			}
			if got := password(); got != "0 Pr3seed-S3cret" {
				t.Fatalf("the password answer is %q", got)
			}
			state, err := os.ReadFile(filepath.Join(w.dir, "terraform.tfstate"))
			if err != nil {
				t.Fatal(err)
			}
			if strings.Contains(string(state), "Pr3seed") || !strings.Contains(string(state), "hmac-sha256:") {
				t.Fatal("state holds the password, or no value_hmac")
			}
			if out := w.mustConn3x("plan", "-no-color"); !strings.Contains(out, "No changes.") {
				t.Fatalf("plan after apply:\n%s", out)
			}

			// A new answer and a new password update in place.
			w.writeAs("main.circuit.hcl", debconfVars{h.port, h.keyFile, h.knownHosts, "Satellite system"})
			w.env = append(w.env, "TF_VAR_db_password=Oth3r-S3cret")
			if out := w.mustConn3x("apply", "-auto-approve", "-no-color"); !strings.Contains(out, "2 changed") {
				t.Fatalf("apply after changing both:\n%s", out)
			}
			if got := h.exec("", "debconf-show", "postfix"); !strings.Contains(got, "* postfix/main_mailer_type: Satellite system\n") {
				t.Fatalf("debconf-show postfix:\n%s", got)
			}
			if got := password(); got != "0 Oth3r-S3cret" {
				t.Fatalf("the password answer is %q", got)
			}
			if out := w.mustConn3x("plan", "-no-color"); !strings.Contains(out, "No changes.") {
				t.Fatalf("plan after the update:\n%s", out)
			}

			// Both answers changed on the host show as drift, the password
			// through its HMAC, and apply sets them again.
			h.exec("postfix postfix/main_mailer_type select Local only\napp app/db_password password changed-by-hand\n", "debconf-set-selections")
			if out := w.mustConn3x("plan", "-no-color"); !strings.Contains(out, "2 to change") {
				t.Fatalf("plan after a change on the host:\n%s", out)
			}
			w.mustConn3x("apply", "-auto-approve", "-no-color")
			if got := password(); got != "0 Oth3r-S3cret" {
				t.Fatalf("the password answer after drift is %q", got)
			}
		})
	}
}

// TestDebconfRefusesRedHat fails with a clear error on a host that has no
// debconf.
func TestDebconfRefusesRedHat(t *testing.T) {
	h := startHost(t, "rocky10")
	w := newWorkdir(t, "debconf")
	w.writeAs("main.circuit.hcl", debconfVars{h.port, h.keyFile, h.knownHosts, "Internet Site"})
	w.env = append(w.env, "TF_VAR_db_password=Pr3seed-S3cret")
	w.mustConn3x("init", "-no-color")
	if out, code := w.conn3x("apply", "-auto-approve", "-no-color"); code == 0 || !strings.Contains(out, "Red Hat family, which has no debconf") {
		t.Fatalf("apply on rocky exited %d:\n%s", code, out)
	}
}
