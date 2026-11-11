// Copyright (c) The Conn3x Authors
// SPDX-License-Identifier: MPL-2.0

package schedule

import (
	"strings"
	"testing"
)

// A crontab step's crontab holds exactly its environment and jobs: other
// jobs, env lines and lines that aren't either go, and are reported; other
// comments and blank lines stay. A second pass changes nothing.
func TestCrontabWant(t *testing.T) {
	c := Crontab{
		User: "deploy",
		Env:  map[string]string{"MAILTO": "ops@example.com", "PATH": "/usr/bin:/bin"},
		Jobs: []Job{
			{Name: "backup", Schedule: "0 3 * * *", Command: "/opt/app/backup --at 100%"},
			{Name: "boot", Schedule: "@reboot", Command: "/opt/app/start"},
		},
	}
	if err := c.Validate(); err != nil {
		t.Fatal(err)
	}
	current := "# my notes\n\nMAILTO=old@example.com\nPATH=/usr/bin:/bin\n*/5 * * * * curl -s https://example.com/ping?token=s3cret\n0 3 * * * /opt/app/backup --at 100\\%\nthis is not a job\n"
	got, gone := c.Want(current)
	want := "# my notes\n\nMAILTO=ops@example.com\nPATH=/usr/bin:/bin\n# conn3x: backup\n0 3 * * * /opt/app/backup --at 100\\%\n# conn3x: boot\n@reboot /opt/app/start\n"
	if got != want {
		t.Errorf("crontab:\n%s\nwant:\n%s", got, want)
	}
	if len(gone) != 3 {
		t.Fatalf("unlisted: %+v", gone)
	}
	kinds := []string{gone[0].Kind, gone[1].Kind, gone[2].Kind}
	if strings.Join(kinds, ",") != "env,job,unreadable" || gone[1].Schedule != "*/5 * * * *" || gone[1].Head != "curl" {
		t.Errorf("unlisted: %+v", gone)
	}
	for _, g := range gone {
		if s := g.String(); strings.Contains(s, "s3cret") || strings.Contains(s, "curl") || strings.Contains(s, "old@example.com") {
			t.Errorf("what state keeps of %+v shows the line: %s", g, s)
		}
	}
	if again, gone := c.Want(got); again != got || len(gone) != 0 {
		t.Errorf("a second pass changed it: %q %+v", again, gone)
	}
	if got, gone := (Crontab{User: "deploy"}).Want(""); got != "" || len(gone) != 0 {
		t.Errorf("nothing listed and nothing there: %q %+v", got, gone)
	}
}

func TestCrontabValidate(t *testing.T) {
	for want, c := range map[string]Crontab{
		"two jobs are named": {User: "deploy", Jobs: []Job{{Name: "a", Schedule: "@daily", Command: "x"}, {Name: "a", Schedule: "@daily", Command: "y"}}},
		"needs five fields":  {User: "deploy", Jobs: []Job{{Name: "a", Schedule: "* * *", Command: "x"}}},
		"single line":        {User: "deploy", Jobs: []Job{{Name: "a", Schedule: "@daily", Command: "x\ny"}}},
		"isn't a variable":   {User: "deploy", Env: map[string]string{"1X": "y"}},
		"may only use":       {User: "deploy", Jobs: []Job{{Name: "a b", Schedule: "@daily", Command: "x"}}},
	} {
		if err := c.Validate(); err == nil || !strings.Contains(err.Error(), want) {
			t.Errorf("%s: %v", want, err)
		}
	}
}
