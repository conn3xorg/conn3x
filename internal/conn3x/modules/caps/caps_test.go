// Copyright (c) The Conn3x Authors
// SPDX-License-Identifier: MPL-2.0

package caps

import "testing"

func TestParseAndString(t *testing.T) {
	for in, want := range map[string]string{
		"cap_net_raw+ep":                          "cap_net_raw=ep",
		"cap_net_raw=pe":                          "cap_net_raw=ep",
		"cap_net_raw,cap_net_bind_service+ep":     "cap_net_bind_service,cap_net_raw=ep",
		"cap_net_raw+e cap_net_raw+p":             "cap_net_raw=ep",
		"cap_net_bind_service=ep cap_sys_nice+ei": "cap_net_bind_service=ep cap_sys_nice=ei",
		"cap_net_raw=":                            "",
	} {
		s, err := Parse(in)
		if err != nil || s.String() != want {
			t.Errorf("%q: %q, %v; want %q", in, s.String(), err, want)
		}
	}
	for _, bad := range []string{"net_raw+ep", "cap_net_raw-ep", "cap_net_raw+x", "CAP_NET_RAW+ep"} {
		if _, err := Parse(bad); err == nil {
			t.Errorf("%q: no error", bad)
		}
	}
}

// getcap prints "path = caps" in older libcap and "path caps" in newer.
func TestParseGetcap(t *testing.T) {
	for out, want := range map[string]string{
		"/usr/bin/ping = cap_net_raw+ep\n": "cap_net_raw=ep",
		"/usr/bin/ping cap_net_raw=ep\n":   "cap_net_raw=ep",
		"":                                 "",
		"/usr/bin/pingx cap_net_raw=ep\n":  "",
	} {
		s, err := parseGetcap(out, "/usr/bin/ping")
		if err != nil || s.String() != want {
			t.Errorf("%q: %q, %v; want %q", out, s.String(), err, want)
		}
	}
}

func TestValidate(t *testing.T) {
	ok, _ := Parse("cap_net_bind_service+ep")
	if err := (File{Path: "/usr/sbin/nginx", Caps: ok}).Validate(); err != nil {
		t.Error(err)
	}
	for name, bad := range map[string]File{
		"relative": {Path: "usr/bin/ping", Caps: ok},
		"none":     {Path: "/usr/bin/ping", Caps: Set{}},
	} {
		if err := bad.Validate(); err == nil {
			t.Errorf("%s: no error", name)
		}
	}
}
