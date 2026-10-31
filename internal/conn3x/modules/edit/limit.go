// Copyright (c) The Conn3x Authors
// SPDX-License-Identifier: MPL-2.0

package edit

import (
	"errors"
	"fmt"
	"regexp"
	"slices"
	"strconv"
	"strings"
)

// limitItems are the items limits.conf(5) names.
var limitItems = []string{"core", "data", "fsize", "memlock", "nofile", "rss", "stack", "cpu", "nproc", "as", "maxlogins", "maxsyslogins", "priority", "locks", "sigpending", "msgqueue", "nice", "rtprio", "chroot"}

var limitDomain = regexp.MustCompile(`^[^\s#]+$`)

// Limit is one PAM limit that should, or should not, be in a limits.conf file.
type Limit struct {
	Domain, Type, Item, Value string
	State                     State // default Present
}

// Validate checks a Limit before anything is edited.
func (l Limit) Validate() error {
	switch l.State {
	case "", Present, Absent:
	default:
		return fmt.Errorf("state must be %q or %q, not %q", Present, Absent, l.State)
	}
	if !limitDomain.MatchString(l.Domain) {
		return fmt.Errorf("domain %q must be one word, with no #", l.Domain)
	}
	if l.Type != "soft" && l.Type != "hard" && l.Type != "-" {
		return fmt.Errorf("type must be \"soft\", \"hard\" or \"-\", not %q", l.Type)
	}
	if !slices.Contains(limitItems, l.Item) {
		return fmt.Errorf("item %q is not one limits.conf knows: %s", l.Item, strings.Join(limitItems, ", "))
	}
	if l.State == Absent {
		if l.Value != "" {
			return errors.New("leave value out with state = \"absent\": the limit goes whatever its value")
		}
		return nil
	}
	n, err := strconv.Atoi(l.Value)
	switch {
	case l.Item == "nice" || l.Item == "priority":
		if err != nil || n < -20 || n > 19 {
			return fmt.Errorf("value %q for %s must be a number from -20 to 19", l.Value, l.Item)
		}
	case l.Value == "unlimited" || l.Value == "infinity":
	case err != nil || n < -1:
		return fmt.Errorf("value %q must be a number, -1, \"unlimited\" or \"infinity\"", l.Value)
	}
	return nil
}

// ApplyLimit returns content with the limit set or removed. Lines are compared
// by their fields, so spacing doesn't count. The first line for the limit
// takes the value and keeps any comment after it; any others go, because PAM
// uses the last one it reads. A line already right, with nothing after it to
// tidy, isn't touched. A new limit goes at the end.
func ApplyLimit(content string, l Limit) (string, error) {
	if err := l.Validate(); err != nil {
		return "", err
	}
	lines, final := split(content)
	var out []string
	found, changed := false, false
	for _, line := range lines {
		rule, comment, _ := strings.Cut(line, "#")
		f := strings.Fields(rule)
		if len(f) != 4 || f[0] != l.Domain || f[1] != l.Type || f[2] != l.Item {
			out = append(out, line)
			continue
		}
		if l.State == Absent || found {
			changed = true
			continue
		}
		found = true
		if f[3] == l.Value {
			out = append(out, line)
			continue
		}
		changed = true
		want := strings.Join([]string{l.Domain, l.Type, l.Item, l.Value}, "\t")
		if comment != "" {
			want += "\t#" + comment
		}
		out = append(out, want)
	}
	if l.State != Absent && !found {
		out = append(out, strings.Join([]string{l.Domain, l.Type, l.Item, l.Value}, "\t"))
		changed = true
	}
	if !changed {
		return content, nil
	}
	return join(out, final || l.State != Absent), nil
}
