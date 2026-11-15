// Copyright (c) The Conn3x Authors
// SPDX-License-Identifier: MPL-2.0

package jsonentities

import (
	"testing"

	"github.com/opentofu/opentofu/internal/addrs"
)

func TestNewResourceAddrConn3xStep(t *testing.T) {
	inst := func(typ, name string, key addrs.InstanceKey) addrs.AbsResourceInstance {
		return addrs.Resource{Mode: addrs.ManagedResourceMode, Type: typ, Name: name}.Instance(key).Absolute(addrs.RootModuleInstance)
	}
	for _, c := range []struct {
		addr addrs.AbsResourceInstance
		want *Conn3xStep
	}{
		{inst("conn3x_command", "box__build", addrs.StringKey("web1")), &Conn3xStep{Circuit: "box", Step: "build", Host: "web1"}},
		{inst("conn3x_package", "base__pkgs", addrs.StringKey("web1/nginx")), &Conn3xStep{Circuit: "base", Step: "pkgs", Host: "web1", Item: "nginx"}},
		{inst("conn3x_package", "base__pkgs", addrs.StringKey("web1/a/b")), &Conn3xStep{Circuit: "base", Step: "pkgs", Host: "web1", Item: "a/b"}},
		{inst("conn3x_file", "plain", addrs.StringKey("web1")), nil},
		{inst("conn3x_file", "a__b", addrs.IntKey(0)), nil},
		{inst("aws_instance", "a__b", addrs.StringKey("x")), nil},
	} {
		got := NewResourceAddr(c.addr).Conn3x
		if (got == nil) != (c.want == nil) || got != nil && *got != *c.want {
			t.Errorf("%s: got %+v, want %+v", c.addr, got, c.want)
		}
	}
}
