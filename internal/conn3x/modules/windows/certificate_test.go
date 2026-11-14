// Copyright (c) The Conn3x Authors
// SPDX-License-Identifier: MPL-2.0

package windows

import "testing"

func TestCertificate(t *testing.T) {
	pfx := Certificate{Path: `C:\certs\web.pfx`, Location: "LocalMachine", Store: "My"}
	if err := pfx.Validate(); err != nil || !pfx.PFX() {
		t.Fatalf("pfx: %v, %v", err, pfx.PFX())
	}
	in := ActualCertificate{InStore: true, HasKey: true, FileExists: true, FileSHA256: "aa"}
	if !pfx.Matches(in, "aa") {
		t.Error("in the store, same file: should match")
	}
	if pfx.Matches(ActualCertificate{InStore: true, FileExists: true, FileSHA256: "aa"}, "aa") {
		t.Error("a PFX without its private key matched")
	}
	if pfx.Matches(ActualCertificate{InStore: true, HasKey: true, FileExists: true, FileSHA256: "bb"}, "aa") {
		t.Error("a renewed file matched")
	}
	if !pfx.Matches(ActualCertificate{InStore: true, HasKey: true}, "aa") {
		t.Error("a file removed after the import should still match")
	}
	cer := Certificate{Path: `C:\certs\ca.cer`, Location: "LocalMachine", Store: "Root"}
	if !cer.Matches(ActualCertificate{InStore: true, FileExists: true, FileSHA256: "cc"}, "cc") || cer.PFX() {
		t.Error("a .cer needs no private key")
	}
	gone := Certificate{Path: `C:\certs\ca.cer`, Location: "LocalMachine", Store: "Root", Absent: true}
	if !gone.Matches(ActualCertificate{}, "") || gone.Matches(ActualCertificate{InStore: true}, "") {
		t.Error("absent")
	}
	for _, bad := range []Certificate{
		{Path: `web.pfx`, Location: "LocalMachine", Store: "My"},
		{Path: `C:\certs\web.txt`, Location: "LocalMachine", Store: "My"},
		{Path: `C:\certs\web.pfx`, Location: "Machine", Store: "My"},
		{Path: `C:\certs\web.pfx`, Location: "LocalMachine", Store: `My\..`},
	} {
		if bad.Validate() == nil {
			t.Errorf("accepted %+v", bad)
		}
	}
}
