// Copyright (c) The Conn3x Authors
// SPDX-License-Identifier: MPL-2.0

package configs

import (
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
)

const rescueSteps = `step "config" {
    file {
      path    = "/etc/app.conf"
      content = "x"
    }
    notify = [handler.restart]
  }
  handler "restart" {
    service {
      name = "app"
    }
  }
  rescue "restore" {
    watches = [step.config, handler.restart]
    command {
      command = "restore"
    }
  }
  rescue "page" {
    watches  = [step.config]
    for_each = ["a", "b"]
    command {
      command = "page ${item.value}"
    }
  }`

func TestRescueInstances(t *testing.T) {
	mod, diags := loadCircuitModule(t, map[string]string{"main.circuit.hcl": onceCircuit("", rescueSteps)})
	if diags.HasErrors() {
		t.Fatal(diags.Error())
	}
	restore := mod.ManagedResources["conn3x_command.app__restore"]
	page := mod.ManagedResources["conn3x_command.app__page"]
	if !Conn3xRescueResource(restore) || Conn3xRescueResource(mod.ManagedResources["conn3x_file.app__config"]) {
		t.Fatal("Conn3xRescueResource is wrong")
	}
	// The second rescue runs after the first, and neither waits for a step.
	if len(page.DependsOn) != 1 || page.DependsOn[0].RootName() != "conn3x_command" || len(restore.DependsOn) != 0 {
		t.Fatalf("depends_on: restore %v, page %v", restore.DependsOn, page.DependsOn)
	}

	if keys, d := instanceKeys(t, restore.ForEach, nil); d.HasErrors() || len(keys) != 0 {
		t.Fatalf("outside a rescue phase: %v, %v", keys, d)
	}
	Conn3xRescueHosts = map[string][]string{"app__restore": {"web1", "db1"}, "app__page": {"web2"}}
	defer func() { Conn3xRescueHosts = nil }()
	if keys, d := instanceKeys(t, restore.ForEach, nil); d.HasErrors() || strings.Join(keys, ",") != "db1,web1" {
		t.Errorf("restore: %v, %v", keys, d)
	}
	if keys, d := instanceKeys(t, page.ForEach, nil); d.HasErrors() || strings.Join(keys, ",") != "web2/a,web2/b" {
		t.Errorf("page: %v, %v", keys, d)
	}
}

func TestRescueErrors(t *testing.T) {
	for want, rescue := range map[string]string{
		"Missing watches in rescue":       `rescue "r" {` + "\n" + `command { command = "x" }` + "\n}",
		"Empty watches in rescue":         `rescue "r" {` + "\nwatches = []\n" + `command { command = "x" }` + "\n}",
		"Invalid watches in rescue":       `rescue "r" {` + "\nwatches = [var.x]\n" + `command { command = "x" }` + "\n}",
		`No step or handler "nope"`:       `rescue "r" {` + "\nwatches = [step.nope]\n" + `command { command = "x" }` + "\n}",
		"Duplicate rescue":                `rescue "config" {` + "\nwatches = [step.config]\n" + `command { command = "x" }` + "\n}",
		`Unsupported argument "notify"`:   `rescue "r" {` + "\nwatches = [step.config]\nnotify = [handler.restart]\n" + `command { command = "x" }` + "\n}",
		`Unsupported argument "run_once"`: `rescue "r" {` + "\nwatches = [step.config]\nrun_once = true\n" + `command { command = "x" }` + "\n}",
	} {
		steps := strings.SplitN(rescueSteps, "  rescue", 2)[0] + rescue
		_, diags := loadCircuitModule(t, map[string]string{"main.circuit.hcl": onceCircuit("", steps)})
		if !diags.HasErrors() || !strings.Contains(diags.Error(), want) {
			t.Errorf("%s: got %v", want, diags)
		}
	}
}

func TestConn3xRescues(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "main.circuit.hcl"), []byte(onceCircuit("", rescueSteps)), 0o644); err != nil {
		t.Fatal(err)
	}
	got, diags := Conn3xRescues(dir)
	if diags.HasErrors() || len(got) != 2 {
		t.Fatalf("%v, %v", got, diags)
	}
	if got[0].Resource() != "app__restore" || !slices.Equal(got[0].Watches, []string{"config", "restart"}) || !slices.Equal(got[1].Watches, []string{"config"}) {
		t.Errorf("got %+v", got)
	}
}
