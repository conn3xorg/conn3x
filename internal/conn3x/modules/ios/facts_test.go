// Copyright (c) The Conn3x Authors
// SPDX-License-Identifier: MPL-2.0

package ios

import "testing"

// Written in the shape show version takes on IOS XE and on classic IOS;
// the lab round checks them against IOL-XE 17.18 and IOSv 15.9 (#1174).
const iosXEVersion = `Cisco IOS XE Software, Version 17.18.01
Cisco IOS Software [Fuji], Linux Software (X86_64BI_LINUX-ADVENTERPRISEK9-M), Version 17.18.1, RELEASE SOFTWARE (fc3)
Technical Support: http://www.cisco.com/techsupport

edge01 uptime is 2 hours, 3 minutes
System returned to ROM by reload
System image file is "unix:/x86_64_crb_linux-adventerprisek9-ms.iol"

cisco IOL-XE (i686) processor with 2069780K/6147K bytes of memory.
Processor board ID 131184641
`

const classicVersion = `Cisco IOS Software, IOSv Software (VIOS-ADVENTERPRISEK9-M), Version 15.9(3)M4, RELEASE SOFTWARE (fc3)
Technical Support: http://www.cisco.com/techsupport

r1 uptime is 1 hour, 2 minutes
System image file is "flash0:/vios-adventerprisek9-m"

Cisco IOSv (revision 1.0) with  with 460137K/62464K bytes of memory.
Processor board ID 9N37ZWU1WLOWUTJXSPXF8
`

func TestParseVersion(t *testing.T) {
	for name, tc := range map[string]struct {
		out  string
		want Facts
	}{
		"IOS XE":  {iosXEVersion, Facts{Hostname: "edge01", Model: "IOL-XE", Version: "17.18.01", Serial: "131184641", Image: "unix:/x86_64_crb_linux-adventerprisek9-ms.iol", Type: "IOS-XE"}},
		"classic": {classicVersion, Facts{Hostname: "r1", Model: "IOSv", Version: "15.9(3)M4", Serial: "9N37ZWU1WLOWUTJXSPXF8", Image: "flash0:/vios-adventerprisek9-m", Type: "IOS"}},
	} {
		got, err := ParseVersion(tc.out)
		if err != nil || got != tc.want {
			t.Errorf("%s: %+v, %v\nwant %+v", name, got, err, tc.want)
		}
	}
	if _, err := ParseVersion("Arista DCS-7050TX\nSoftware image version: 4.37.0F\n"); err == nil {
		t.Error("an EOS show version read as IOS")
	}
}
