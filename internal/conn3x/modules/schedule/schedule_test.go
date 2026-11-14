// Copyright (c) The Conn3x Authors
// SPDX-License-Identifier: MPL-2.0

package schedule

import (
	"strings"
	"testing"
)

func TestCronContent(t *testing.T) {
	got, err := Cron{Name: "backup", Schedule: "30 2 * * *", Command: "/usr/local/bin/backup --quiet"}.Content()
	if err != nil {
		t.Fatal(err)
	}
	want := "# Managed by Conn3x.\nSHELL=/bin/sh\nPATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin\n30 2 * * * root /usr/local/bin/backup --quiet\n"
	if got != want {
		t.Fatalf("got %q", got)
	}
	got, _ = Cron{Name: "x", Schedule: "@daily", User: "app", Command: "true"}.Content()
	if !strings.HasSuffix(got, "@daily app true\n") {
		t.Fatalf("got %q", got)
	}
}

func TestCronValidate(t *testing.T) {
	for _, bad := range []Cron{
		{Name: "has.dot", Schedule: "* * * * *", Command: "x"},
		{Name: "ok", Schedule: "* * * *", Command: "x"},
		{Name: "ok", Schedule: "@sometimes", Command: "x"},
		{Name: "ok", Schedule: "* * * * *", Command: ""},
		{Name: "ok", Schedule: "* * * * *", Command: "a\nb"},
		{Name: "ok", Schedule: "* * * * *", Command: "x", User: "Bad User"},
	} {
		if bad.Validate() == nil {
			t.Errorf("accepted %+v", bad)
		}
	}
	if err := (Cron{Name: "log-rotate_2", Schedule: "*/5 1-3 * * mon-fri", Command: "x"}).Validate(); err != nil {
		t.Errorf("valid cron rejected: %v", err)
	}
}

func TestTimerUnits(t *testing.T) {
	tm := Timer{Name: "backup", OnCalendar: "*-*-* 02:30:00", Command: "/usr/local/bin/backup", Persistent: true}
	svc, tmr, err := tm.Units()
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{"[Service]", "Type=oneshot", "ExecStart=/usr/local/bin/backup", "User=root", "Description=backup (managed by Conn3x)"} {
		if !strings.Contains(svc, want) {
			t.Errorf("service missing %q:\n%s", want, svc)
		}
	}
	for _, want := range []string{"[Timer]", "OnCalendar=*-*-* 02:30:00", "Persistent=true", "WantedBy=timers.target"} {
		if !strings.Contains(tmr, want) {
			t.Errorf("timer missing %q:\n%s", want, tmr)
		}
	}
}

func TestTimerValidate(t *testing.T) {
	for _, bad := range []Timer{
		{Name: "a b", OnCalendar: "daily", Command: "x"},
		{Name: "ok", OnCalendar: "", Command: "x"},
		{Name: "ok", OnCalendar: "daily\nExecStart=evil", Command: "x"},
		{Name: "ok", OnCalendar: "daily", Command: "a\nb"},
	} {
		if bad.Validate() == nil {
			t.Errorf("accepted %+v", bad)
		}
	}
}

// cron reads an unescaped % as a newline, and systemd as a specifier.
func TestPercentIsEscaped(t *testing.T) {
	got, err := Cron{Name: "stamp", Schedule: "@daily", Command: "date +%F >> /var/log/stamp"}.Content()
	if err != nil || !strings.HasSuffix(got, `@daily root date +\%F >> /var/log/stamp`+"\n") {
		t.Fatalf("cron = %q, %v", got, err)
	}
	svc, _, err := Timer{Name: "stamp", OnCalendar: "daily", Command: "date +%F", Description: "100% daily"}.Units()
	if err != nil || !strings.Contains(svc, "ExecStart=date +%%F\n") || !strings.Contains(svc, "Description=100%% daily\n") {
		t.Fatalf("service = %q, %v", svc, err)
	}
}

func TestParseTimerRoundTrips(t *testing.T) {
	for _, want := range []Timer{
		{Name: "backup", OnCalendar: "*-*-* 02:30:00", Command: "/usr/local/bin/backup --to s3://b/%Y", Persistent: true},
		{Name: "report", OnCalendar: "weekly", Command: "/opt/report", User: "app", Description: "Weekly report"},
	} {
		svc, tmr, err := want.Units()
		if err != nil {
			t.Fatal(err)
		}
		got, why := ParseTimer(want.Name, svc, tmr)
		if why != "" || got != want {
			t.Errorf("%s: got %+v (%s), want %+v", want.Name, got, why, want)
		}
	}
	// Written by hand: comments, spacing and a Unit= line it can't own.
	svc := "[Unit]\nDescription=Clean tmp\n\n[Service]\n# nightly\nExecStart = /usr/bin/find /tmp -mtime +7 -delete\n"
	if got, why := ParseTimer("clean", svc, "[Timer]\nOnCalendar = daily\n[Install]\nWantedBy=timers.target\n"); why != "" || got.OnCalendar != "daily" || got.Command != "/usr/bin/find /tmp -mtime +7 -delete" || got.Description != "Clean tmp" {
		t.Errorf("by hand: %+v, %s", got, why)
	}
	for name, units := range map[string][2]string{
		"two calendars": {svc, "[Timer]\nOnCalendar=daily\nOnCalendar=weekly\n"},
		"boot":          {svc, "[Timer]\nOnBootSec=5min\n"},
		"delay":         {svc, "[Timer]\nOnCalendar=daily\nRandomizedDelaySec=1h\n"},
		"two commands":  {"[Service]\nExecStart=/a\nExecStart=/b\n", "[Timer]\nOnCalendar=daily\n"},
		"simple":        {"[Service]\nType=simple\nExecStart=/a\n", "[Timer]\nOnCalendar=daily\n"},
	} {
		if _, why := ParseTimer("x", units[0], units[1]); why == "" {
			t.Errorf("%s: adopted", name)
		}
	}
}
