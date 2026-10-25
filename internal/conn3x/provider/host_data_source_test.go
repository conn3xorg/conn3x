// Copyright (c) The Conn3x Authors
// SPDX-License-Identifier: MPL-2.0

package provider

import (
	"context"
	"testing"

	"github.com/zclconf/go-cty/cty"

	"github.com/opentofu/opentofu/internal/providers"
)

func TestHostDataSourceIsServed(t *testing.T) {
	p := &Provider{}
	schema, ok := p.GetProviderSchema(context.Background()).DataSources["conn3x_host"]
	if !ok {
		t.Fatal("conn3x_host is not in the schema")
	}
	for _, attr := range []string{"os_family", "os_id", "os_version", "arch", "cpus", "memory_mb", "ipv4"} {
		if a := schema.Block.Attributes[attr]; a == nil || !a.Computed {
			t.Errorf("%s is missing or not computed", attr)
		}
	}
	resp := p.ReadDataSource(context.Background(), providers.ReadDataSourceRequest{TypeName: "conn3x_nope", Config: cty.EmptyObjectVal})
	if !resp.Diagnostics.HasErrors() {
		t.Error("read an unknown data source")
	}
}
