// Copyright (c) The Conn3x Authors
// SPDX-License-Identifier: MPL-2.0

package ansible

import (
	"strings"
	"testing"
)

// A handler that only reloads systemd has no Conn3x handler: Conn3x
// reloads systemd itself before acting on a unit whose file changed. A
// task that notifies it still converts, with a note saying so.
func TestDaemonReloadHandler(t *testing.T) {
	res := convertString(t, `- hosts: all
  become: true
  tasks:
    - name: Unit
      copy: {dest: /etc/systemd/system/app.service, content: "[Service]\nExecStart=/bin/true\n", mode: "0644"}
      notify: [reload systemd, restart app]
  handlers:
    - name: reload systemd
      systemd_service: {daemon_reload: true}
    - name: restart app
      service: {name: app, state: restarted}
    - name: reload and restart
      systemd: {name: app, state: restarted, daemon_reload: true}
`)
	hcl := string(res.HCL)
	if res.Converted != 1 || len(res.Notes) != 1 || !strings.Contains(res.Notes[0].Reason, "only runs systemctl daemon-reload") {
		t.Fatalf("converted %d, notes %+v, review %+v\n%s", res.Converted, res.Notes, res.Review, hcl)
	}
	if !strings.Contains(hcl, "handler.restart_app") || strings.Contains(hcl, "handler.reload_systemd") {
		t.Errorf("want notify on restart_app only:\n%s", hcl)
	}
}
