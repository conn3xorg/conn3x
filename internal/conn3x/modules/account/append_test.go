// Copyright (c) The Conn3x Authors
// SPDX-License-Identifier: MPL-2.0

package account

import (
	"slices"
	"testing"
)

// With AppendGroups, other groups on the host are fine; without, they're a
// change.
func TestAppendGroups(t *testing.T) {
	u := User{Exists: true, Groups: []string{"audio", "docker"}}
	docker, video := []string{"docker"}, []string{"docker", "video"}
	for name, c := range map[string]struct {
		s    UserSpec
		want bool
	}{
		"append, already in":       {UserSpec{Name: "a", Groups: &docker, AppendGroups: true}, false},
		"append, one missing":      {UserSpec{Name: "a", Groups: &video, AppendGroups: true}, true},
		"complete list, has extra": {UserSpec{Name: "a", Groups: &docker}, true},
	} {
		if got := UserNeedsChange(c.s, u); got != c.want {
			t.Errorf("%s: %v", name, got)
		}
	}
	if got := (UserSpec{Groups: &[]string{"video", "docker", "video"}}).missingGroups(u); !slices.Equal(got, []string{"video"}) {
		t.Errorf("missing: %q", got)
	}
}
