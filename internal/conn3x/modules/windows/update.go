// Copyright (c) The Conn3x Authors
// SPDX-License-Identifier: MPL-2.0

package windows

import (
	"context"
	"encoding/json"
	"fmt"
	"maps"
	"regexp"
	"slices"
	"strings"
	"time"

	"github.com/opentofu/opentofu/internal/conn3x/modules/windows/ps"
)

// UpdateCategories are the Windows Update classifications a windows_update
// step can name, with the IDs Windows Update gives them.
var UpdateCategories = map[string]string{
	"Applications":      "5c9376ab-8ce6-464a-b136-22113dd69801",
	"Connectors":        "434de588-ed14-48f5-8eed-a15e09a991f6",
	"CriticalUpdates":   "e6cf1350-c01b-414d-a61f-263d14d133b4",
	"DefinitionUpdates": "e0789628-ce08-4437-be74-2495b842f43b",
	"DeveloperKits":     "e140075d-8433-45c3-ad87-e72345b36078",
	"Drivers":           "ebfc1fc5-71a4-4f7b-9aca-3b9a503104a0",
	"FeaturePacks":      "b54e7d24-7add-428f-8b75-90a396fa584f",
	"Guidance":          "9511d615-35b2-47bb-927f-f73d8e9260bb",
	"SecurityUpdates":   "0fa1201d-4330-4fa8-8ae9-b877473b6441",
	"ServicePacks":      "68c5b0a3-d1a6-4553-ae49-01d3a7827828",
	"Tools":             "b4832bd8-e735-4761-8daf-37f882276dab",
	"UpdateRollups":     "28bc880e-0592-4cbf-8f95-c79b17911d5f",
	"Updates":           "cd5ffd1e-e932-4e3a-bf74-18bf0b1bbd83",
	"Upgrades":          "3689bdc8-b205-4af4-8d4a-a63924c5e9d5",
}

// DefaultUpdateCategories is what a windows_update step installs when it
// names no categories: the ones a monthly patch run is for.
var DefaultUpdateCategories = []string{"CriticalUpdates", "SecurityUpdates"}

var kbNumber = regexp.MustCompile(`^KB[0-9]{6,8}$`)

// Update is the Windows updates a host should have installed: those in
// Categories, only the KB numbers in Accept when it's set, never those in
// Reject.
type Update struct {
	Categories     []string
	Accept, Reject []string
}

// Validate checks the names and numbers before anything reaches a host.
func (u Update) Validate() error {
	for _, c := range u.Categories {
		if _, ok := UpdateCategories[c]; !ok {
			return fmt.Errorf("%q is not a Windows Update category; use one of %s", c, strings.Join(slices.Sorted(maps.Keys(UpdateCategories)), ", "))
		}
	}
	for _, kb := range slices.Concat(u.Accept, u.Reject) {
		if !kbNumber.MatchString(kb) {
			return fmt.Errorf("%q is not a KB number, such as KB5034441", kb)
		}
	}
	return nil
}

func (u Update) args() map[string]any {
	cats := u.Categories
	if len(cats) == 0 {
		cats = DefaultUpdateCategories
	}
	ids := make([]string, len(cats))
	for i, c := range cats {
		ids[i] = UpdateCategories[c]
	}
	return map[string]any{"categories": ids, "accept": nonNil(u.Accept), "reject": nonNil(u.Reject)}
}

func nonNil(s []string) []string {
	if s == nil {
		return []string{}
	}
	return s
}

// PendingUpdates lists the updates waiting to install, each as its KB
// number and title, such as "KB5034441 2024-01 Security Update for ...".
func PendingUpdates(ctx context.Context, r ps.Runner, u Update) ([]string, error) {
	if err := u.Validate(); err != nil {
		return nil, err
	}
	res, err := ps.Read(ctx, r, script("read_updates.ps1"), u.args())
	if err != nil {
		return nil, err
	}
	var a struct {
		Pending []string `json:"pending"`
	}
	if err := json.Unmarshal(res.Value, &a); err != nil {
		return nil, fmt.Errorf("reading the updates waiting: %w", err)
	}
	return nonNil(a.Pending), nil
}

// ApplyUpdates downloads and installs the updates waiting, as SYSTEM through
// a one-off scheduled task, and reports whether Windows wants a reboot. It
// never reboots. Updates that didn't install are an error naming them,
// after the rest have installed.
func ApplyUpdates(ctx context.Context, r ps.Runner, u Update, timeout time.Duration) (installed []string, restart bool, err error) {
	if err := u.Validate(); err != nil {
		return nil, false, err
	}
	args := u.args()
	args["timeout_seconds"] = int(timeout.Seconds())
	// The SSH session waits on the task, so it gets a little longer.
	res, err := ps.Apply(ctx, r, script("apply_updates.ps1"), args, timeout+2*time.Minute)
	if err != nil {
		return nil, false, err
	}
	var a struct {
		Installed []string `json:"installed"`
		Failed    []string `json:"failed"`
		Restart   bool     `json:"restart"`
	}
	if err := json.Unmarshal(res.Value, &a); err != nil {
		return nil, false, fmt.Errorf("reading the update result: %w", err)
	}
	if len(a.Failed) > 0 {
		return a.Installed, a.Restart, fmt.Errorf("these updates didn't install: %s", strings.Join(a.Failed, "; "))
	}
	return nonNil(a.Installed), a.Restart, nil
}
