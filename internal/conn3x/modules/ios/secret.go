// Copyright (c) The Conn3x Authors
// SPDX-License-Identifier: MPL-2.0

package ios

import (
	"errors"
	"fmt"
	"regexp"
	"slices"
	"strings"

	"github.com/opentofu/opentofu/internal/conn3x/modules/eos"
)

// SecretPrefix is line up to its secret, such as "tacacs-server key" for
// "tacacs-server key 7 0207165218120E", or "ntp authentication-key 1" for
// "ntp authentication-key 1 md5 <secret> 7". IOS writes its secret lines
// the way EOS does, so this is EOS's reading of them.
func SecretPrefix(line string) (string, error) { return eos.SecretPrefix(line) }

// snmpCommunity matches an SNMP community line, whose secret is also its
// name: no prefix can tell one community from another.
var snmpCommunity = regexp.MustCompile(`(?i)^snmp-server\s+community\s`)

func (c Config) secretLine(have string) bool {
	return slices.ContainsFunc(c.Prefixes, func(p string) bool { return strings.HasPrefix(have, p+" ") })
}

// secretsMissing are the prefixes no line in have starts with.
func (c Config) secretsMissing(have []string) []string {
	var missing []string
	for _, p := range c.Prefixes {
		if !slices.ContainsFunc(have, func(h string) bool { return strings.HasPrefix(h, p+" ") }) {
			missing = append(missing, p)
		}
	}
	return missing
}

// plain is have without the lines the secrets own.
func (c Config) plain(have []string) []string {
	return slices.DeleteFunc(slices.Clone(have), c.secretLine)
}

// validateSecrets checks lines_wo. Errors never quote a secret line, since
// they're printed.
func (c Config) validateSecrets() error {
	seen := map[string]bool{}
	for _, l := range c.Secrets {
		if checkLine(l) != nil {
			return errors.New("a line in lines_wo is not a single CLI line as show running-config prints it, holds a ?, or would leave configuration mode")
		}
		if snmpCommunity.MatchString(l) {
			return errors.New("lines_wo can't hold an snmp-server community line: the community is both its name and its secret, and the device can't show which one is this step's, so a change or removal would take out communities others set. Use an SNMPv3 user instead")
		}
		p, err := SecretPrefix(l)
		if err != nil {
			return errors.New("a line in lines_wo holds no secret Conn3x knows, such as a key, secret or password; put it in lines instead")
		}
		if seen[p] {
			return fmt.Errorf("two lines in lines_wo start %q, and the device can't show which secret each holds; give each its own start", p)
		}
		seen[p] = true
		for _, plain := range c.Lines {
			if strings.HasPrefix(plain, p+" ") {
				return fmt.Errorf("line %q in lines starts like a line in lines_wo (%q), which owns every line starting that way; take it out of one of them", plain, p)
			}
		}
	}
	return nil
}

// secretCommands are the secret lines to send: all of them on Resend, as
// when one changed, or the ones whose prefix the device has no line for.
// IOS replaces a key or secret in place when the command is typed again,
// and applies each line as it comes, so the old line is never taken off
// first: that would leave the device without the secret for a moment, and
// after the new line it would take the new one off.
func (c Config) secretCommands(have []string) []string {
	absent := c.secretsMissing(have)
	var cmds []string
	for _, l := range c.Secrets {
		p, _ := SecretPrefix(l)
		if c.Resend || slices.Contains(absent, p) {
			cmds = append(cmds, l)
		}
	}
	return cmds
}
