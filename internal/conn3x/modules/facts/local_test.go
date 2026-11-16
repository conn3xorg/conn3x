// Copyright (c) The Conn3x Authors
// SPDX-License-Identifier: MPL-2.0

package facts

import (
	"encoding/base64"
	"strings"
	"testing"
)

func TestParseLocal(t *testing.T) {
	b := func(s string) string { return base64.StdEncoding.EncodeToString([]byte(s)) }
	out := strings.Join([]string{
		"/etc/conn3x/facts.d/rack.json", b(`{"row": "B", "unit": 12}`),
		"/etc/ansible/facts.d/owner.fact", b("[team]\nName = platform\n; a comment\noncall: yes\n"),
		"/etc/ansible/facts.d/rack.fact", b(`{"row": "ignored"}`),
	}, "\n") + "\n"
	got, err := parseLocal(out)
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 2 || string(got["rack"]) != `{"row": "B", "unit": 12}` || string(got["owner"]) != `{"team":{"name":"platform","oncall":"yes"}}` {
		t.Errorf("got %q", got)
	}

	for in, want := range map[string]string{
		"/etc/conn3x/facts.d/x.json\n" + b("[a]\nb=c\n") + "\n":         "isn't valid JSON",
		"/etc/ansible/facts.d/x.fact\n" + b("just text\n") + "\n":       "neither JSON nor INI",
		"/etc/ansible/facts.d/x.fact\n!it exited with an error: boom\n": "x.fact: it exited with an error: boom",
		"/etc/conn3x/facts.d/9lives.json\n" + b("{}") + "\n":            "name it with letters",
		"/etc/conn3x/facts.d/a.json\n":                                  "unexpected output",
	} {
		if _, err := parseLocal(in); err == nil || !strings.Contains(err.Error(), want) {
			t.Errorf("%q: got %v, want %q", in, err, want)
		}
	}
	if got, err := parseLocal(""); err != nil || len(got) != 0 {
		t.Errorf("no files: %v %v", got, err)
	}
}
