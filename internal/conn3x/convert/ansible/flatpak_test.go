// Copyright (c) The Conn3x Authors
// SPDX-License-Identifier: MPL-2.0

package ansible

import (
	"strings"
	"testing"
)

func TestConvertFlatpak(t *testing.T) {
	for task, want := range map[string][]string{
		"community.general.flatpak: { name: org.gnome.Calculator }":                                    {"flatpak {", `name = "org.gnome.Calculator"`},
		"flatpak: { name: [org.gnome.Calculator, org.videolan.VLC], method: user, state: latest }":     {`name   = "org.gnome.Calculator"`, `name   = "org.videolan.VLC"`, `method = "user"`, `state  = "latest"`},
		"flatpak: { name: org.gnome.Totem, remote: flathub-beta, state: absent, executable: flatpak }": {`remote = "flathub-beta"`, `state  = "absent"`},
	} {
		res := convertString(t, "- hosts: all\n  become: true\n  tasks:\n    - "+task+"\n")
		if res.Converted != 1 || len(res.Review) != 0 {
			t.Errorf("%s: converted %d, review %v", task, res.Converted, res.Review)
		}
		for _, w := range want {
			if !strings.Contains(string(res.HCL), w) {
				t.Errorf("%s: missing %s:\n%s", task, w, res.HCL)
			}
		}
	}
	for task, reason := range map[string]string{
		"flatpak: { name: app/org.gnome.Calculator/x86_64/stable }":                          "a ref or URL",
		"flatpak: { name: 'https://flathub.org/repo/appstream/org.gnome.gedit.flatpakref' }": "a ref or URL",
		"flatpak: { name: org.gnome.Calculator, executable: /opt/flatpak/bin/flatpak }":      "runs",
		"flatpak: { name: org.gnome.Calculator, no_dependencies: true }":                     "no_dependencies",
		"flatpak: { name: org.gnome.Calculator, state: installed }":                          "no Conn3x equivalent",
	} {
		res := convertString(t, "- hosts: all\n  tasks:\n    - "+task+"\n")
		if res.Converted != 0 || len(res.Review) != 1 || !strings.Contains(res.Review[0].Reason, reason) {
			t.Errorf("%s: %+v", task, res.Review)
		}
	}
}
