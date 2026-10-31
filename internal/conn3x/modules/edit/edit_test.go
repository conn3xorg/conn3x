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

func TestINI(t *testing.T) {
	x := func(v string) INI { return INI{Section: "a", Option: "x", Value: v} }
	for name, tc := range map[string]struct {
		in   string
		spec INI
		want string
	}{
		"adds after the section's last setting": {"[a]\nx = 1\n# tail\n\n[b]\ny = 2\n", INI{Section: "a", Option: "z", Value: "3"}, "[a]\nx = 1\nz = 3\n# tail\n\n[b]\ny = 2\n"},
		"changes the value":                     {"[a]\nx = 1\n[b]\nx = 1\n", x("2"), "[a]\nx = 2\n[b]\nx = 1\n"},
		"normalises the line":                   {"[a]\n  x=1 ; old\n", x("2"), "[a]\nx = 2\n"},
		"no_extra_spaces":                       {"[a]\nx = 1\n", INI{Section: "a", Option: "x", Value: "2", NoExtraSpaces: true}, "[a]\nx=2\n"},
		"keeps comments by default":             {"; top\n[a]\n# x = 1\ny=2\n", x("9"), "; top\n[a]\n# x = 1\ny=2\nx = 9\n"},
		"uncomment takes a commented line":      {"[a]\n# x = 1\ny=2\n", INI{Section: "a", Option: "x", Value: "9", Uncomment: true}, "[a]\nx = 9\ny=2\n"},
		"uncomment ignores prose":               {"[a]\n# x is it\n", INI{Section: "a", Option: "x", Value: "9", Uncomment: true}, "[a]\nx = 9\n# x is it\n"},
		"repeats collapse to the first":         {"[a]\nx = 1\nw=1\nx = 3\n", x("9"), "[a]\nx = 9\nw=1\n"},
		"first section of a name only":          {"[a]\nx = 1\n[b]\n[a]\nx = 2\n", x("9"), "[a]\nx = 9\n[b]\n[a]\nx = 2\n"},
		"adds a missing section":                {"[a]\nx = 1", INI{Section: "n", Option: "x", Value: "9"}, "[a]\nx = 1\n[n]\nx = 9\n"},
		"no section goes before the first":      {"p = 1\n[a]\nq = 1\n", INI{Option: "q", Value: "9"}, "p = 1\nq = 9\n[a]\nq = 1\n"},
		"no section in an empty file":           {"", INI{Option: "q", Value: "9"}, "q = 9\n"},
		"prefix isn't a match":                  {"[a]\nxy = 1\nX = 1\n", x("2"), "[a]\nxy = 1\nX = 1\nx = 2\n"},
		"bare option is a match":                {"[a]\nx\n", x("1"), "[a]\nx = 1\n"},
		"empty value":                           {"[a]\nx = 1\n", x(""), "[a]\nx = \n"},
		"value with an equals sign":             {"[a]\nx = 1\n", x("a=b"), "[a]\nx = a=b\n"},
		"crlf kept":                             {"[a]\r\nx = 1\r\n", x("2"), "[a]\r\nx = 2\r\n"},
		"crlf new line":                         {"[a]\r\n", x("2"), "[a]\r\nx = 2\r\n"},
		"adds the final newline":                {"[a]\nx = 1", x("1"), "[a]\nx = 1\n"},
		"byte order mark kept when unchanged":   {"\xef\xbb\xbf[a]\nx = 1\n", x("1"), "\xef\xbb\xbf[a]\nx = 1\n"},
		"byte order mark dropped on a change":   {"\xef\xbb\xbf[a]\nx = 1\n", x("2"), "[a]\nx = 2\n"},
		"absent":                                {"[a]\nx = 1\n#x = 2\nx = 3\ny=1\n", INI{Section: "a", Option: "x", State: Absent}, "[a]\n#x = 2\ny=1\n"},
		"absent keeps other sections":           {"[a]\ny=1\n[b]\nx=1\n", INI{Section: "a", Option: "x", State: Absent}, "[a]\ny=1\n[b]\nx=1\n"},
		"absent without a section":              {"q=1\n[a]\nq=1\n", INI{Option: "q", State: Absent}, "[a]\nq=1\n"},
		"absent from a missing section":         {"[b]\nx=1\n", INI{Section: "a", Option: "x", State: Absent}, "[b]\nx=1\n"},
	} {
		t.Run(name, func(t *testing.T) {
			got, err := ApplyINI(tc.in, tc.spec)
			if err != nil {
				t.Fatal(err)
			}
			if got != tc.want {
				t.Fatalf("got %q, want %q", got, tc.want)
			}
			if again, _ := ApplyINI(got, tc.spec); again != got {
				t.Fatalf("not idempotent: %q then %q", got, again)
			}
		})
	}
	for _, bad := range []INI{{}, {Option: "a=b"}, {Option: " a"}, {Option: "#a"}, {Option: "[a"}, {Option: "a\nb"}, {Option: "a", Section: "b]"}, {Option: "a", Value: "b\nc"}, {Option: "a", State: "gone"}} {
		if bad.Validate() == nil {
			t.Errorf("Validate(%+v) accepted", bad)
		}
	}
}

func TestReplace(t *testing.T) {
	for name, tc := range map[string]struct {
		in   string
		spec Replace
		want string
	}{
		"every match":          {"foo bar foo\nfoo\n", Replace{`foo`, "baz"}, "baz bar baz\nbaz\n"},
		"no match":             {"a\n", Replace{`foo`, "baz"}, "a\n"},
		"anchors at each line": {"a=1\nb=2\na=3\n", Replace{`^a=.*$`, "a=0"}, "a=0\nb=2\na=0\n"},
		"dot stops at a line":  {"ab\ncd\n", Replace{`a.*`, "z"}, "z\ncd\n"},
		"across lines":         {"a\nb\n", Replace{`a\nb`, "c"}, "c\n"},
		"group":                {"port 80\n", Replace{`port (\d+)`, "listen ${1}0"}, "listen 800\n"},
		"named group":          {"k=v\n", Replace{`(?P<key>\w+)=v`, "${key}:v"}, "k:v\n"},
		"dollar":               {"cost\n", Replace{`cost`, "$$5"}, "$5\n"},
		"deletes":              {"a#b\n", Replace{`#.*`, ""}, "a\n"},
		"final newline kept":   {"foo", Replace{`foo`, "bar"}, "bar"},
	} {
		t.Run(name, func(t *testing.T) {
			got, err := ApplyReplace(tc.in, tc.spec)
			if err != nil {
				t.Fatal(err)
			}
			if got != tc.want {
				t.Fatalf("got %q, want %q", got, tc.want)
			}
			if again, _ := ApplyReplace(got, tc.spec); again != got {
				t.Fatalf("not idempotent: %q then %q", got, again)
			}
		})
	}
}

// A replacement the regexp matches again would change the file on every
// plan, so it's stopped: at validate when the text is fixed, otherwise when
// the file shows it, and in both cases before anything is written.
func TestReplaceThatNeverSettles(t *testing.T) {
	for _, r := range []Replace{{`foo`, "foofoo"}, {`foo`, "foobar"}, {`^a`, "ab"}, {`x*`, "y"}} {
		if r.Validate() == nil {
			t.Errorf("Validate(%+v) accepted", r)
		}
	}
	if err := (Replace{`(foo)`, "$1$1"}).Validate(); err != nil {
		t.Fatal(err)
	}
	if _, err := ApplyReplace("foo\n", Replace{`(foo)`, "$1$1"}); err == nil {
		t.Error("a growing backreference was applied")
	}
	if got, err := ApplyReplace("bar\n", Replace{`(foo)`, "$1$1"}); err != nil || got != "bar\n" {
		t.Errorf("no match: %q, %v", got, err)
	}
	// These match their own output but leave it alone, so they settle.
	for _, r := range []Replace{{`a+`, "a"}, {`^foo$`, "foo"}, {`foo$`, "foo bar"}} {
		if err := r.Validate(); err != nil {
			t.Errorf("Validate(%+v): %v", r, err)
		}
	}
}

func TestReplaceRefusesBadInput(t *testing.T) {
	for _, r := range []Replace{{"", "x"}, {"(", "x"}, {`(a)`, "$2"}, {`(a)`, "$1x"}, {`(a)`, "${nope}"}} {
		if r.Validate() == nil {
			t.Errorf("Validate(%+v) accepted", r)
		}
	}
}

func TestApplyLimit(t *testing.T) {
	nofile := Limit{Domain: "joe", Type: "soft", Item: "nofile", Value: "64000"}
	gone := nofile
	gone.State, gone.Value = Absent, ""
	for name, c := range map[string]struct {
		in   string
		l    Limit
		want string
	}{
		"adds to an empty file":       {"", nofile, "joe\tsoft\tnofile\t64000\n"},
		"adds at the end":             {"# head\n@g - core 1\n# End of file\n", nofile, "# head\n@g - core 1\n# End of file\njoe\tsoft\tnofile\t64000\n"},
		"same value isn't rewritten":  {"joe  soft nofile   64000 # why\n", nofile, "joe  soft nofile   64000 # why\n"},
		"no ending newline, same":     {"joe soft nofile 64000", nofile, "joe soft nofile 64000"},
		"changes value, keeps note":   {"joe soft nofile 1024 # old\n", nofile, "joe\tsoft\tnofile\t64000\t# old\n"},
		"drops later copies":          {"joe soft nofile 1\nx - core 1\njoe soft nofile 2\n", nofile, "joe\tsoft\tnofile\t64000\nx - core 1\n"},
		"other type or item stays":    {"joe hard nofile 5\njoe soft nproc 5\njo soft nofile 5\n", nofile, "joe hard nofile 5\njoe soft nproc 5\njo soft nofile 5\njoe\tsoft\tnofile\t64000\n"},
		"comment lines don't count":   {"#joe soft nofile 1\n", nofile, "#joe soft nofile 1\njoe\tsoft\tnofile\t64000\n"},
		"domain is case sensitive":    {"JOE soft nofile 1\n", nofile, "JOE soft nofile 1\njoe\tsoft\tnofile\t64000\n"},
		"absent removes every copy":   {"joe soft nofile 1\nx - core 1\njoe soft nofile 2\n", gone, "x - core 1\n"},
		"absent with nothing to take": {"x - core 1", gone, "x - core 1"},
	} {
		t.Run(name, func(t *testing.T) {
			got, err := ApplyLimit(c.in, c.l)
			if err != nil || got != c.want {
				t.Fatalf("got %q, %v\nwant %q", got, err, c.want)
			}
			again, err := ApplyLimit(got, c.l)
			if err != nil || again != got {
				t.Fatalf("not settled: %q, %v", again, err)
			}
		})
	}
}

func TestLimitValidate(t *testing.T) {
	ok := func(d, ty, it, v string) Limit { return Limit{Domain: d, Type: ty, Item: it, Value: v} }
	for _, l := range []Limit{ok("joe", "soft", "nofile", "1"), ok("*", "-", "core", "unlimited"), ok("@g", "hard", "as", "infinity"), ok("1000:", "hard", "as", "-1"), ok("a", "soft", "nice", "-20"), ok("a", "soft", "chroot", "0"), {Domain: "a", Type: "-", Item: "core", State: Absent}} {
		if err := l.Validate(); err != nil {
			t.Errorf("%+v: %v", l, err)
		}
	}
	for _, l := range []Limit{ok("", "soft", "nofile", "1"), ok("a b", "soft", "nofile", "1"), ok("a#", "soft", "nofile", "1"), ok("a", "both", "nofile", "1"), ok("a", "soft", "bogus", "1"), ok("a", "soft", "nofile", ""), ok("a", "soft", "nofile", "-2"), ok("a", "soft", "nofile", "1\n"), ok("a", "soft", "nice", "20"), ok("a", "soft", "nice", "unlimited"), {Domain: "a", Type: "-", Item: "core", Value: "1", State: Absent}, {Domain: "a", Type: "-", Item: "core", Value: "1", State: "x"}} {
		if err := l.Validate(); err == nil {
			t.Errorf("accepted %+v", l)
		}
	}
}
