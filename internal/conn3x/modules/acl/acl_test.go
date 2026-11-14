// Copyright (c) The Conn3x Authors
// SPDX-License-Identifier: MPL-2.0

package acl

import "testing"

func TestFindAndMatch(t *testing.T) {
	out := "user::rwx\nuser:alice:r-x\ngroup::r-x\ngroup:ops:rwx\nmask::rwx\nother::r-x\ndefault:user::rwx\ndefault:user:alice:r--\ndefault:other::---\n"
	for _, c := range []struct {
		e    Entry
		want bool
	}{
		{Entry{Type: "user", Entity: "alice", Permissions: "xr"}, true},
		{Entry{Type: "user", Entity: "alice", Permissions: "r"}, false},
		{Entry{Type: "user", Entity: "alice", Permissions: "r", Default: true}, true},
		{Entry{Type: "group", Entity: "ops", Permissions: "rwx"}, true},
		{Entry{Type: "other", Permissions: "rx"}, true},
		{Entry{Type: "mask", Permissions: "rwx"}, true},
		{Entry{Type: "other", Default: true}, true},
		{Entry{Type: "user", Entity: "bob", Absent: true}, true},
		{Entry{Type: "user", Entity: "alice", Absent: true}, false},
		{Entry{Type: "user", Entity: "ali", Permissions: "rx"}, false},
	} {
		perms, ok, _ := find(out, c.e.key())
		if got := c.e.Matches(perms, ok); got != c.want {
			t.Errorf("%+v: %v (found %q %v)", c.e, got, perms, ok)
		}
	}
	for _, bad := range []Entry{
		{Path: "rel", Type: "user", Entity: "a"},
		{Path: "/x", Type: "owner", Entity: "a"},
		{Path: "/x", Type: "user"},
		{Path: "/x", Type: "user", Entity: "a b"},
		{Path: "/x", Type: "mask", Entity: "a"},
		{Path: "/x", Type: "other", Absent: true},
		{Path: "/x", Type: "user", Entity: "a", Permissions: "rwxs"},
	} {
		if bad.Validate() == nil {
			t.Errorf("%+v passed", bad)
		}
	}
}
