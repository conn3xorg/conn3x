// Copyright (c) The Conn3x Authors
// SPDX-License-Identifier: MPL-2.0

package provider

import (
	"net"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"

	"github.com/zclconf/go-cty/cty"

	"github.com/opentofu/opentofu/internal/conn3x/transport/ssh/sshtest"
)

// A port change plans a replacement only when the new port reaches another
// machine: one whose recorded host key isn't the old port's.
func TestPortChangeReplacesOnlyForAnotherMachine(t *testing.T) {
	f := newFileTest(t)
	state := f.create("x", nil)
	newPort := f.server.Port + 1
	oldAddr := net.JoinHostPort(f.server.Host, strconv.Itoa(f.server.Port))
	newAddr := net.JoinHostPort(f.server.Host, strconv.Itoa(newPort))
	other := sshtest.NewKeys(t).Host.PublicKey()

	for _, tc := range []struct {
		name        string
		lines       []string
		wantReplace bool
	}{
		{"same machine on a new port", []string{
			sshtest.KnownHostsLine(oldAddr, f.server.HostKey),
			sshtest.KnownHostsLine(newAddr, f.server.HostKey),
		}, false},
		{"another machine on the new port", []string{
			sshtest.KnownHostsLine(oldAddr, f.server.HostKey),
			sshtest.KnownHostsLine(newAddr, other),
		}, true},
		{"new port not recorded", []string{
			sshtest.KnownHostsLine(oldAddr, f.server.HostKey),
		}, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			kh := filepath.Join(t.TempDir(), "known_hosts")
			if err := os.WriteFile(kh, []byte(strings.Join(tc.lines, "\n")+"\n"), 0o600); err != nil {
				t.Fatal(err)
			}
			prior := withSSHAttrs(state, map[string]cty.Value{"known_hosts_file": cty.StringVal(kh)})
			conn := prior.GetAttr("ssh").AsValueMap()
			conn["port"] = cty.NumberIntVal(int64(newPort))
			f.conn = cty.ObjectVal(conn)
			resp := f.plan(prior, f.config(map[string]cty.Value{"content": cty.StringVal("x")}))
			if got := len(resp.RequiresReplace) > 0; got != tc.wantReplace {
				t.Fatalf("replace = %v (%#v), want %v", got, resp.RequiresReplace, tc.wantReplace)
			}
		})
	}
}

func withSSHAttrs(state cty.Value, attrs map[string]cty.Value) cty.Value {
	conn := state.GetAttr("ssh").AsValueMap()
	for k, v := range attrs {
		conn[k] = v
	}
	vals := state.AsValueMap()
	vals["ssh"] = cty.ObjectVal(conn)
	return cty.ObjectVal(vals)
}
