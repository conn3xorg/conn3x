// Copyright (c) The Conn3x Authors
// SPDX-License-Identifier: MPL-2.0

//go:build e2e

package e2e

import (
	"encoding/json"
	"strconv"
	"strings"
	"testing"
)

// conn3x_packages gives each package's version as the package manager
// prints it, and conn3x_services each service's state, with masked and a
// disabled unit never read as enabled.
func TestPackagesAndServicesData(t *testing.T) {
	for _, image := range linuxImages {
		t.Run(image, func(t *testing.T) {
			h := startHost(t, image)
			h.exec("", "sh", "-c", `printf '[Unit]\nDescription=demo\n[Service]\nExecStart=/bin/true\n[Install]\nWantedBy=multi-user.target\n' >/etc/systemd/system/conn3x-demo.service
printf '[Unit]\nDescription=instance\n[Service]\nExecStart=/bin/sleep infinity\n' >/etc/systemd/system/conn3x-inst@.service
systemctl daemon-reload && systemctl mask conn3x-masked.service
systemctl start "conn3x-inst@$(systemd-escape a-b).service"`)
			w := newWorkdir(t, "inventory")
			w.write(circuitVars{Port: h.port, KeyFile: h.keyFile, KnownHosts: h.knownHosts})
			w.mustConn3x("init", "-no-color")
			w.mustConn3x("apply", "-auto-approve", "-no-color")

			want := "dpkg-query -W -f '${Version}' bash"
			if rpmImage(image) {
				want = "rpm -q --qf '%{EPOCHNUM}:%{VERSION}-%{RELEASE}' bash"
			}
			if got, want := w.mustConn3x("output", "-raw", "bash"), h.exec("", "sh", "-c", want); got != want {
				t.Errorf("bash is %q, the package manager says %q", got, want)
			}
			if got := w.mustConn3x("output", "-raw", "bash_versions"); got != w.mustConn3x("output", "-raw", "bash") {
				t.Errorf("bash's versions are %q", got)
			}
			if n, err := strconv.Atoi(w.mustConn3x("output", "-raw", "packages")); err != nil || n < 100 {
				t.Errorf("%d packages, %v", n, err)
			}

			type svc struct {
				State         string `json:"state"`
				Enabled       bool   `json:"enabled"`
				UnitFileState string `json:"unit_file_state"`
			}
			read := func(name string) svc {
				var s svc
				if err := json.Unmarshal([]byte(w.mustConn3x("output", "-json", name)), &s); err != nil {
					t.Fatalf("%s: %v", name, err)
				}
				return s
			}
			if s := read("sshd"); s.State != "active" {
				t.Errorf("sshd: %+v", s)
			}
			if s := read("masked"); s.Enabled || s.UnitFileState != "masked" {
				t.Errorf("a masked unit: %+v", s)
			}
			if s := read("demo"); s.Enabled || s.State != "inactive" || s.UnitFileState != "disabled" {
				t.Errorf("a disabled unit: %+v", s)
			}
			// systemd escapes the instance name a-b as a\x2db.
			if s := read("instance"); s.State != "active" {
				t.Errorf("an instance with an escaped name: %+v", s)
			}

			// Enabled and started by hand: the next plan reads it so.
			h.exec("", "systemctl", "enable", "--now", "conn3x-demo.service")
			w.mustConn3x("apply", "-auto-approve", "-no-color")
			if s := read("demo"); !s.Enabled || s.UnitFileState != "enabled" || !strings.Contains("active inactive", s.State) {
				t.Errorf("an enabled unit: %+v", s)
			}
		})
	}
}
