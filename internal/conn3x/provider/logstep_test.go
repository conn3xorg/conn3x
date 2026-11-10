// Copyright (c) The Conn3x Authors
// SPDX-License-Identifier: MPL-2.0

package provider

import (
	"bytes"
	"log"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/zclconf/go-cty/cty"
)

func TestLogStepNamesTheStepAndTheWait(t *testing.T) {
	var buf bytes.Buffer
	log.SetOutput(&buf)
	t.Cleanup(func() { log.SetOutput(os.Stderr) })

	start := time.Now().Add(-3 * time.Second)
	state := cty.ObjectVal(map[string]cty.Value{
		"id":       cty.StringVal("10.0.0.5:feature:Web-Server"),
		"password": cty.StringVal("hunter2"),
	})
	logStep("read", "conn3x_windows_feature", state, start, start.Add(2*time.Second))
	got := buf.String()
	for _, want := range []string{"[DEBUG] conn3x: read conn3x_windows_feature 10.0.0.5:feature:Web-Server took 3", "2s of it waiting for a reboot"} {
		if !strings.Contains(got, want) {
			t.Errorf("log %q lacks %q", got, want)
		}
	}
	if strings.Contains(got, "hunter2") {
		t.Errorf("log %q has an attribute's value", got)
	}

	// A new step's id isn't known yet; it's named by its host instead.
	buf.Reset()
	planned := cty.ObjectVal(map[string]cty.Value{
		"id":  cty.UnknownVal(cty.String),
		"ssh": cty.ObjectVal(map[string]cty.Value{"host": cty.StringVal("10.0.0.6"), "port": cty.NullVal(cty.Number)}),
	})
	logStep("apply", "conn3x_file", planned, time.Now(), time.Now())
	if got := buf.String(); !strings.Contains(got, "apply conn3x_file on 10.0.0.6 took") || strings.Contains(got, "waiting") {
		t.Errorf("log %q", got)
	}
}
