// Copyright (c) The Conn3x Authors
// SPDX-License-Identifier: MPL-2.0

package provider

import (
	"strings"
	"testing"
)

// A timer whose drop-ins change it isn't adopted from its units alone: the
// step would hold what the units say, not what systemd runs.
func TestTimerJSONRefusesDropIns(t *testing.T) {
	const service = "[Service]\nType=oneshot\nExecStart=/usr/local/bin/backup.sh\n"
	const timer = "[Timer]\nOnCalendar=daily\n"
	if got := timerJSON("backup", service, timer, nil); !strings.Contains(got, `"on_calendar":"daily"`) {
		t.Fatalf("without drop-ins: %s", got)
	}
	got := timerJSON("backup", service, timer, []string{"/etc/systemd/system/backup.timer.d"})
	if !strings.Contains(got, `"skip"`) || !strings.Contains(got, "/etc/systemd/system/backup.timer.d") {
		t.Fatalf("with a drop-in: %s", got)
	}
}
