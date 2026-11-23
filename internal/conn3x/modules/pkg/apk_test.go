// Copyright (c) The Conn3x Authors
// SPDX-License-Identifier: MPL-2.0

package pkg

import (
	"strings"
	"testing"
)

// apk list's lines, as Alpine 3.22 prints them.
func TestAPKVersion(t *testing.T) {
	out := "tree-doc-2.2.1-r0 aarch64 {tree} (GPL-2.0-or-later)\ntree-2.2.1-r0 aarch64 {tree} (GPL-2.0-or-later) [installed]\n"
	for name, want := range map[string]string{"tree": "2.2.1-r0", "tree-doc": "2.2.1-r0", "tre": "", "nginx": ""} {
		if got := apkVersion(out, name); got != want {
			t.Errorf("%s: %q, want %q", name, got, want)
		}
	}
	if got := apkVersion("", "tree"); got != "" {
		t.Errorf("not installed: %q", got)
	}
	if !versionMatches("2.2.1-r0", "2.2.1") || !versionMatches("2.2.1-r0", "2.2.1-r0") {
		t.Error("a version without its -r part doesn't match")
	}
}

func TestAPKApply(t *testing.T) {
	no := false
	for name, tc := range map[string]struct {
		d    Desired
		want string
	}{
		"install": {Desired{Name: "tree", State: Present}, "apk add -q --no-cache 'tree'"},
		"pin":     {Desired{Name: "tree", State: Present, Version: "2.2.1-r0"}, "apk add -q --no-cache 'tree=2.2.1-r0'"},
		"latest":  {Desired{Name: "tree", State: Latest}, "apk add -q --no-cache --upgrade 'tree'"},
		"remove":  {Desired{Name: "tree", State: Absent}, "apk del -q 'tree'"},
	} {
		h := &scriptedHost{answers: []answer{{"apk", ok("")}}}
		if err := Apply(ctx, h, APK, tc.d); err != nil {
			t.Errorf("%s: %v", name, err)
			continue
		}
		if got := strings.Join(h.ran, "\n"); !strings.Contains(got, tc.want) {
			t.Errorf("%s: ran %q, want %q", name, got, tc.want)
		}
	}
	if err := Apply(ctx, &scriptedHost{}, APK, Desired{Name: "tree", State: Present, InstallRecommends: &no}); err == nil {
		t.Error("install_recommends on Alpine wasn't refused")
	}
	if _, err := ReadHold(ctx, &scriptedHost{}, APK, "tree"); err == nil || !strings.Contains(err.Error(), "/etc/apk/world") {
		t.Errorf("hold on Alpine: %v", err)
	}
}

func TestAPKInventory(t *testing.T) {
	got, err := parseInventory(APK, "aarch64\ntree\taarch64\t2.2.1-r0\nca-certificates-bundle\taarch64\t20250911-r0\n")
	if err != nil || got["tree"][0] != "2.2.1-r0" || got["ca-certificates-bundle"][0] != "20250911-r0" {
		t.Errorf("%v, %v", got, err)
	}
}
