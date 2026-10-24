// Copyright (c) The Conn3x Authors
// SPDX-License-Identifier: MPL-2.0

package edit

import "testing"

func TestLine(t *testing.T) {
	for name, tc := range map[string]struct {
		in   string
		spec Line
		want string
	}{
		"append when missing":                  {"a\nb\n", Line{Line: "c"}, "a\nb\nc\n"},
		"no change when present":               {"a\nc\nb\n", Line{Line: "c"}, "a\nc\nb\n"},
		"append to file without final newline": {"a", Line{Line: "b"}, "a\nb\n"},
		"empty file":                           {"", Line{Line: "x"}, "x\n"},
		"regexp replaces last match": {"PermitRootLogin yes\n#x\nPermitRootLogin maybe\n",
			Line{Regexp: `^PermitRootLogin\b`, Line: "PermitRootLogin no"},
			"PermitRootLogin yes\n#x\nPermitRootLogin no\n"},
		"regexp no match appends":      {"a\n", Line{Regexp: `^Port `, Line: "Port 2222"}, "a\nPort 2222\n"},
		"regexp no match, line exists": {"Port 2222\n", Line{Regexp: `^#Port `, Line: "Port 2222"}, "Port 2222\n"},
		"insert_after":                 {"[main]\nx=1\n[other]\n", Line{Line: "y=2", InsertAfter: `^\[main\]`}, "[main]\ny=2\nx=1\n[other]\n"},
		"insert_before":                {"a\nEND\n", Line{Line: "b", InsertBefore: "^END$"}, "a\nb\nEND\n"},
		"insert_before BOF":            {"a\n", Line{Line: "#!/bin/sh", InsertBefore: "BOF"}, "#!/bin/sh\na\n"},
		"anchor missing appends":       {"a\n", Line{Line: "b", InsertAfter: "^nope"}, "a\nb\n"},
		"absent by line":               {"a\nb\na\n", Line{Line: "a", State: Absent}, "b\n"},
		"absent by regexp":             {"x=1\ny=2\nx=3\n", Line{Regexp: "^x=", State: Absent}, "y=2\n"},
		"absent when missing":          {"a\n", Line{Line: "z", State: Absent}, "a\n"},
		"crlf kept untouched":          {"a\r\nb\r\n", Line{Line: "a\r"}, "a\r\nb\r\n"},
	} {
		t.Run(name, func(t *testing.T) {
			got, err := ApplyLine(tc.in, tc.spec)
			if err != nil {
				t.Fatal(err)
			}
			if got != tc.want {
				t.Fatalf("got %q, want %q", got, tc.want)
			}
			// Applying twice changes nothing more.
			again, _ := ApplyLine(got, tc.spec)
			if again != got {
				t.Fatalf("not idempotent: %q then %q", got, again)
			}
		})
	}
}

func TestLineValidate(t *testing.T) {
	for _, bad := range []Line{
		{},
		{Line: "a\nb"},
		{Line: "x", Regexp: "("},
		{Line: "x", InsertAfter: "a", InsertBefore: "b"},
		{Line: "x", State: "gone"},
	} {
		if bad.Validate() == nil {
			t.Errorf("Validate(%+v) accepted", bad)
		}
	}
	if (Line{Regexp: "^x=", State: Absent}).Validate() != nil {
		t.Error("absent by regexp without line rejected")
	}
}

func TestBlock(t *testing.T) {
	spec := Block{Content: "net.ipv4.ip_forward = 1\nvm.swappiness = 10"}
	got, err := ApplyBlock("# kernel\n", spec)
	if err != nil {
		t.Fatal(err)
	}
	want := "# kernel\n# BEGIN CONN3X MANAGED BLOCK\nnet.ipv4.ip_forward = 1\nvm.swappiness = 10\n# END CONN3X MANAGED BLOCK\n"
	if got != want {
		t.Fatalf("insert:\n%q\nwant\n%q", got, want)
	}
	spec.Content = "vm.swappiness = 5"
	got, _ = ApplyBlock(got+"tail\n", spec)
	want = "# kernel\n# BEGIN CONN3X MANAGED BLOCK\nvm.swappiness = 5\n# END CONN3X MANAGED BLOCK\ntail\n"
	if got != want {
		t.Fatalf("replace:\n%q\nwant\n%q", got, want)
	}
	if again, _ := ApplyBlock(got, spec); again != got {
		t.Fatal("block not idempotent")
	}
	gone, _ := ApplyBlock(got, Block{State: Absent})
	if gone != "# kernel\ntail\n" {
		t.Fatalf("absent: %q", gone)
	}
}

func TestBlockCustomMarkerAndPosition(t *testing.T) {
	spec := Block{Content: "x", Marker: "// {mark} app", InsertBefore: "BOF"}
	got, _ := ApplyBlock("rest\n", spec)
	if got != "// BEGIN app\nx\n// END app\nrest\n" {
		t.Fatalf("got %q", got)
	}
}

func TestBlockRejectsBrokenMarkers(t *testing.T) {
	if _, err := ApplyBlock("# BEGIN CONN3X MANAGED BLOCK\nx\n", Block{Content: "y"}); err == nil {
		t.Fatal("a begin marker without an end was accepted")
	}
	if (Block{Content: "x", Marker: "no placeholder"}).Validate() == nil {
		t.Fatal("marker without {mark} accepted")
	}
}
