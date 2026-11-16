// Copyright (c) The Conn3x Authors
// SPDX-License-Identifier: MPL-2.0

package provider

import (
	"context"
	"encoding/base64"
	"fmt"
	"strings"
	"testing"
)

// winSysImportID is the import ID a circuit writes for a step on h.
func winSysImportID(h *winFakeHost, args string) string {
	c := h.conn
	ssh := fmt.Sprintf(`{"host":%q,"port":%s,"user":%q,"private_key_file":%q,"known_hosts_file":%q,"agent":false}`,
		c.GetAttr("host").AsString(), c.GetAttr("port").AsBigFloat().String(), c.GetAttr("user").AsString(),
		c.GetAttr("private_key_file").AsString(), c.GetAttr("known_hosts_file").AsString())
	return fmt.Sprintf(`{"v":%d,"key":"web1","ssh":%s,"args":%s}`, importVersion, ssh, args)
}

// Each Windows import asks the host whether the object is there before the
// read, whose in_sync can't tell a missing object from a different one.
func TestWinImportMissingObjects(t *testing.T) {
	notAD := map[string]any{"role": 2, "domain": "WORKGROUP"}
	for typ, c := range map[string]struct {
		args, script string
		answer       any
		what         string
	}{
		"conn3x_windows_service":              {`{"name":"W3SVC"}`, "read_service.ps1", map[string]any{"exists": false}, "service W3SVC"},
		"conn3x_windows_registry_value":       {`{"key":"HKLM\\SOFTWARE\\App","name":"Level","type":"dword"}`, "read_registry.ps1", map[string]any{"exists": false}, "registry value Level"},
		"conn3x_windows_feature":              {`{"name":"Web-Server"}`, "read_feature.ps1", map[string]any{"exists": true, "state": "Available"}, "feature Web-Server"},
		"conn3x_windows_user":                 {`{"name":"alice"}`, "read_user.ps1", map[string]any{"exists": false}, "local user alice"},
		"conn3x_windows_group":                {`{"name":"Ops"}`, "read_group.ps1", map[string]any{"exists": false}, "local group Ops"},
		"conn3x_windows_package":              {`{"product_code":"{11111111-2222-3333-4444-555555555555}","source":"C:/pkg/app.msi"}`, "read_package.ps1", map[string]any{"installed": false}, "MSI package"},
		"conn3x_windows_firewall_rule":        {`{"name":"web","protocol":"tcp","local_ports":["443"]}`, "read_firewall_rule.ps1", map[string]any{"exists": false}, "firewall rule web"},
		"conn3x_windows_scheduled_task":       {`{"name":"cleanup","execute":"C:/tools/cleanup.exe","user":"SYSTEM"}`, "read_task.ps1", map[string]any{"exists": false}, "scheduled task cleanup"},
		"conn3x_windows_iis_app_pool":         {`{"name":"app"}`, "read_iis_app_pool.ps1", map[string]any{"installed": false}, "IIS application pool app"},
		"conn3x_windows_iis_site":             {`{"name":"app","physical_path":"C:/sites/app","app_pool":"app","binding":[{"port":8080}]}`, "read_iis_site.ps1", map[string]any{"installed": true, "exists": false}, "IIS site app"},
		"conn3x_windows_acl":                  {`{"path":"C:/srv/app","entry":[{"principal":"S-1-5-32-544","rights":["FullControl"]}]}`, "read_path.ps1", map[string]any{"kind": "file", "link_on_way": `C:\srv`}, "file or folder"},
		"conn3x_windows_dns_client":           {`{"interface":"Ethernet","servers":["10.0.0.4"]}`, "read_dns_client.ps1", map[string]any{"found": false}, "network interface Ethernet"},
		"conn3x_windows_ad_ou":                {`{"name":"Servers"}`, "read_ad_ou.ps1", map[string]any{"ad": true, "exists": false}, "organizational unit"},
		"conn3x_windows_ad_group":             {`{"name":"AppOps","members":["alice"]}`, "read_ad_group.ps1", map[string]any{"ad": true, "exists": false}, "Active Directory group AppOps"},
		"conn3x_windows_ad_user":              {`{"name":"alice"}`, "read_ad_user.ps1", map[string]any{"ad": true, "exists": false}, "Active Directory user alice"},
		"conn3x_windows_ad_forest":            {`{"domain_name":"lab.example.com"}`, "read_ad_forest.ps1", notAD, "forest lab.example.com"},
		"conn3x_windows_ad_domain":            {`{"domain_name":"emea.lab.example.com","username":"admin@lab.example.com"}`, "read_ad_forest.ps1", notAD, "domain emea.lab.example.com"},
		"conn3x_windows_ad_domain_controller": {`{"domain_name":"lab.example.com","username":"LAB\\admin"}`, "read_ad_forest.ps1", notAD, "domain controller in lab.example.com"},
		"conn3x_windows_domain_membership":    {`{"domain":"lab.example.com","username":"LAB\\joiner"}`, "read_ad_forest.ps1", notAD, "membership of domain lab.example.com"},
	} {
		t.Run(typ, func(t *testing.T) {
			h := newWinFakeHost(t)
			h.on(c.script, c.answer)
			_, err := ReadExisting(context.Background(), typ, winSysImportID(h, c.args))
			if err == nil || !strings.Contains(err.Error(), "web1 doesn't have "+c.what) {
				t.Errorf("err = %v", err)
			}
			if len(h.sent(c.script)) != 1 {
				t.Errorf("asked the host %d times", len(h.sent(c.script)))
			}
		})
	}
}

func TestWinImportFoundObject(t *testing.T) {
	h := newWinFakeHost(t)
	h.on("read_service.ps1", map[string]any{"exists": true, "start": "Automatic", "status": "Running"})
	state, err := ReadExisting(context.Background(), "conn3x_windows_service", winSysImportID(h, `{"name":"W3SVC","state":"running"}`))
	if err != nil {
		t.Fatal(err)
	}
	if !winSynced(t, state) || !strings.HasSuffix(state.GetAttr("id").AsString(), ":windows_service:W3SVC") {
		t.Errorf("state %#v", state)
	}
	// The probe, then the read.
	if n := len(h.sent("read_service.ps1")); n != 2 {
		t.Errorf("read the service %d times", n)
	}
	h.fail("read_service.ps1", "WMI is broken")
	if _, err := ReadExisting(context.Background(), "conn3x_windows_service", winSysImportID(h, `{"name":"W3SVC","state":"running"}`)); err == nil || !strings.Contains(err.Error(), "WMI is broken") {
		t.Errorf("a failed probe: %v", err)
	}
}

// An imported windows_file takes its content from the host, so the first
// plan compares content and not content with nothing.
func TestWinImportFileFillsContent(t *testing.T) {
	h := newWinFakeHost(t)
	h.on("read_path.ps1", map[string]any{"kind": "file", "sha256": digest("hello\r\n"), "owner_trusted": true})
	h.on("read_file_content.ps1", map[string]any{"ok": true, "content": base64.StdEncoding.EncodeToString([]byte("hello\r\n"))})
	id := winSysImportID(h, `{"path":"C:/app/motd.txt"}`)
	state, err := ReadExisting(context.Background(), "conn3x_windows_file", id)
	if err != nil {
		t.Fatal(err)
	}
	if got := state.GetAttr("content"); !known(got) || got.AsString() != "hello\r\n" {
		t.Errorf("content = %#v", got)
	}
	if got := h.sent("read_file_content.ps1"); len(got) != 1 || got[0]["path"] != "C:/app/motd.txt" {
		t.Errorf("read_file_content sent %v", got)
	}

	// Changed between the read and the content read.
	h.on("read_file_content.ps1", map[string]any{"ok": true, "content": base64.StdEncoding.EncodeToString([]byte("bye\r\n"))})
	if _, err := ReadExisting(context.Background(), "conn3x_windows_file", id); err == nil || !strings.Contains(err.Error(), "changed while it was being imported") {
		t.Errorf("err = %v", err)
	}
	h.on("read_file_content.ps1", map[string]any{"ok": false, "why": "it is larger than 1 MiB"})
	if _, err := ReadExisting(context.Background(), "conn3x_windows_file", id); err == nil || !strings.Contains(err.Error(), "larger than 1 MiB") {
		t.Errorf("err = %v", err)
	}
}
