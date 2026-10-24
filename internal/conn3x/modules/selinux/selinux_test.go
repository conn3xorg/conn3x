// Copyright (c) The Conn3x Authors
// SPDX-License-Identifier: MPL-2.0

package selinux

import "testing"

func TestValidate(t *testing.T) {
	if err := ValidateBoolean("httpd_can_network_connect"); err != nil {
		t.Fatal(err)
	}
	for _, bad := range []string{"", "httpd can", "x;reboot", "../x"} {
		if ValidateBoolean(bad) == nil {
			t.Errorf("accepted boolean %q", bad)
		}
	}
	if err := (Fcontext{Target: "/srv/www(/.*)?", Type: "httpd_sys_content_t"}).Validate(); err != nil {
		t.Fatal(err)
	}
	for _, bad := range []Fcontext{
		{Target: "srv/www", Type: "httpd_sys_content_t"},
		{Target: "/srv/www", Type: "httpd sys"},
		{Target: "/srv/www\n/etc", Type: "httpd_sys_content_t"},
		{Target: "/srv/www", Type: ""},
	} {
		if bad.Validate() == nil {
			t.Errorf("accepted %+v", bad)
		}
	}
}

func TestRestorePath(t *testing.T) {
	for target, want := range map[string]string{
		"/srv/www(/.*)?":          "/srv/www",
		"/srv/www":                "/srv/www",
		"/var/lib/app/[^/]+\\.db": "/var/lib/app",
		"/(.*)?":                  "",
		"/opt/my.app(/.*)?":       "/opt/my.app",
		"/srv/www.*":              "/srv",
	} {
		if got := (Fcontext{Target: target}).RestorePath(); got != want {
			t.Errorf("RestorePath(%q) = %q, want %q", target, got, want)
		}
	}
}

func TestParseBoolean(t *testing.T) {
	for in, want := range map[string]bool{"1 1": true, "0 0": false, "1 0": true} {
		got, err := parseBoolean(in)
		if err != nil || got != want {
			t.Errorf("parseBoolean(%q) = %v, %v", in, got, err)
		}
	}
	if _, err := parseBoolean(""); err == nil {
		t.Error("accepted empty input")
	}
}

func TestLocalType(t *testing.T) {
	out := `/srv/www(/.*)?                                     all files          system_u:object_r:httpd_sys_content_t:s0
/srv/www/cgi(/.*)?                                 all files          system_u:object_r:httpd_sys_script_exec_t:s0
`
	if got := localType(out, "/srv/www(/.*)?"); got != "httpd_sys_content_t" {
		t.Errorf("got %q", got)
	}
	if got := localType(out, "/srv"); got != "" {
		t.Errorf("matched a prefix: %q", got)
	}
}
