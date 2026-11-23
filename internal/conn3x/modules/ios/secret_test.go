// Copyright (c) The Conn3x Authors
// SPDX-License-Identifier: MPL-2.0

package ios

import (
	"slices"
	"strings"
	"testing"
)

const secretConfig = `hostname r1
tacacs-server key 7 0207165218120E
ntp authentication-key 1 md5 104D000A0618 7
!
tacacs server ise1
 address ipv4 192.0.2.5
 key 7 060506324F41
!
`

func TestConfigSecrets(t *testing.T) {
	top := Config{Secrets: []string{"tacacs-server key NewKey"}, Prefixes: []string{"tacacs-server key"}}
	if !top.InSync(secretConfig) {
		t.Errorf("an encrypted key the device holds reads as out of sync: %q", top.Commands(secretConfig))
	}
	// A rotation sends the line again; IOS replaces the key in place, so
	// the old line is never taken off first.
	top.Resend = true
	if got := top.Commands(secretConfig); !slices.Equal(got, []string{"tacacs-server key NewKey"}) {
		t.Errorf("resend: %q", got)
	}
	under := Config{Parents: []string{"tacacs server ise2"}, Lines: []string{"address ipv4 192.0.2.6"}, Secrets: []string{"key S3cret"}, Prefixes: []string{"key"}}
	if got, want := under.Commands(secretConfig), []string{"tacacs server ise2", " address ipv4 192.0.2.6", " key S3cret"}; !slices.Equal(got, want) {
		t.Errorf("a new server: %q, want %q", got, want)
	}
	// Block mode leaves the lines a secret owns alone.
	block := Config{Parents: []string{"tacacs server ise1"}, Lines: []string{"address ipv4 192.0.2.5"}, Match: MatchBlock, Secrets: []string{"key S3cret"}, Prefixes: []string{"key"}}
	if got := block.Commands(secretConfig); got != nil {
		t.Errorf("block mode with the key: %q", got)
	}
	if got, want := block.RemoveCommands(secretConfig), []string{"tacacs server ise1", " no address ipv4 192.0.2.5", " no key 7 060506324F41"}; !slices.Equal(got, want) {
		t.Errorf("RemoveCommands = %q, want %q", got, want)
	}
}

func TestConfigSecretsValidate(t *testing.T) {
	ok := Config{Lines: []string{"ntp server 192.0.2.1"}, Secrets: []string{"ntp authentication-key 1 md5 K3y", "tacacs-server key K3y"}}
	if err := ok.Validate(); err != nil {
		t.Error(err)
	}
	if err := (Config{Secrets: []string{"tacacs-server key K3y"}}).Validate(); err != nil {
		t.Errorf("secrets alone: %v", err)
	}
	for name, bad := range map[string]Config{
		"community":  {Secrets: []string{"snmp-server community public RO"}},
		"no secret":  {Secrets: []string{"ntp server 192.0.2.1"}},
		"same start": {Secrets: []string{"tacacs-server key A", "tacacs-server key B"}},
		"overlap":    {Lines: []string{"tacacs-server key plain"}, Secrets: []string{"tacacs-server key K3y"}},
		"a ?":        {Secrets: []string{"tacacs-server key K3y?"}},
		"mode word":  {Secrets: []string{"end"}},
	} {
		err := bad.Validate()
		if err == nil {
			t.Errorf("%s: no error", name)
			continue
		}
		// Errors are printed, so they never quote a secret.
		if strings.Contains(err.Error(), "K3y") || strings.Contains(err.Error(), "public") {
			t.Errorf("%s: the error quotes the secret: %v", name, err)
		}
	}
}
