// Copyright (c) The Conn3x Authors
// SPDX-License-Identifier: MPL-2.0

package edit

import "testing"

// The line steps conn3x convert makes from postgresql_pg_hba, on the
// pg_hba.conf files Debian and Red Hat ship: a new rule goes above the
// first catch-all rule of its kind, after Debian's local all postgres
// peer, and a rule with the same key and another method is replaced where
// it stands.
func TestPgHbaLines(t *testing.T) {
	const debian = "# comment\n" +
		"local   all             postgres                                peer\n" +
		"local   all             all                                     peer\n" +
		"host    all             all             127.0.0.1/32            scram-sha-256\n" +
		"local   replication     all                                     peer\n"
	const redhat = "local   all             all                                     peer\n" +
		"host    all             all             127.0.0.1/32            ident\n"
	hostRule := Line{
		Line:         "host app app 10.0.0.0/24 scram-sha-256",
		Regexp:       `^\s*host\s+app\s+app\s+10\.0\.0\.0/24(\s|$)`,
		InsertBefore: `^\s*host(ssl|nossl|gssenc|nogssenc)?\s+all\s+all\s`,
	}
	localAll := Line{
		Line:         "local all all md5",
		Regexp:       `^\s*local\s+all\s+all(\s|$)`,
		InsertBefore: `^\s*local\s+all\s+all\s`,
	}
	for name, c := range map[string]struct {
		l        Line
		in, want string
	}{
		"host rule on debian": {hostRule, debian, "# comment\n" +
			"local   all             postgres                                peer\n" +
			"local   all             all                                     peer\n" +
			"host app app 10.0.0.0/24 scram-sha-256\n" +
			"host    all             all             127.0.0.1/32            scram-sha-256\n" +
			"local   replication     all                                     peer\n"},
		"host rule on red hat": {hostRule, redhat, "local   all             all                                     peer\n" +
			"host app app 10.0.0.0/24 scram-sha-256\n" +
			"host    all             all             127.0.0.1/32            ident\n"},
		// Same key as Debian's local all all peer: replaced in place, after
		// local all postgres peer, which Conn3x logs in by.
		"local all all replaces in place": {localAll, debian, "# comment\n" +
			"local   all             postgres                                peer\n" +
			"local all all md5\n" +
			"host    all             all             127.0.0.1/32            scram-sha-256\n" +
			"local   replication     all                                     peer\n"},
		"same key, new method": {hostRule, "host app app 10.0.0.0/24 md5\nhost all all 0.0.0.0/0 reject\n",
			"host app app 10.0.0.0/24 scram-sha-256\nhost all all 0.0.0.0/0 reject\n"},
		// hostssl isn't host: a different key, so a new line.
		"hostssl is another key": {hostRule, "hostssl app app 10.0.0.0/24 md5\n",
			"hostssl app app 10.0.0.0/24 md5\nhost app app 10.0.0.0/24 scram-sha-256\n"},
		// A longer network that starts the same isn't the same key.
		"10.0.0.0/2 isn't 10.0.0.0/24": {hostRule, "host app app 10.0.0.0/2 md5\n",
			"host app app 10.0.0.0/2 md5\nhost app app 10.0.0.0/24 scram-sha-256\n"},
		"no catch-all: at the end": {hostRule, "local all postgres peer\n",
			"local all postgres peer\nhost app app 10.0.0.0/24 scram-sha-256\n"},
	} {
		got, err := ApplyLine(c.in, c.l)
		if err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		if got != c.want {
			t.Errorf("%s:\n%s\nwant:\n%s", name, got, c.want)
		}
	}
}
