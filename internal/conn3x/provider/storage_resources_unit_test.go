// Copyright (c) The Conn3x Authors
// SPDX-License-Identifier: MPL-2.0

package provider

import (
	"fmt"
	"strings"
	"sync"
	"testing"

	"github.com/zclconf/go-cty/cty"

	"github.com/opentofu/opentofu/internal/providers"
)

// unitDisk answers the storage steps' scripts as a host with one blank
// 1 GiB disk, /dev/vdb, whose contents change when mkfs, vgcreate,
// lvcreate or parted runs.
type unitDisk struct {
	mu     sync.Mutex
	fs     string
	vg, lv bool
	part   bool
	gone   bool // the disk isn't there: every script fails
}

func (d *unitDisk) answer(script string) (string, int) {
	d.mu.Lock()
	defer d.mu.Unlock()
	if d.gone {
		return "/dev/vdb isn't a block device on this host", 1
	}
	switch {
	case strings.Contains(script, `echo "type=$t"`):
		return fmt.Sprintf("type=%s\ndevsize=1073741824\nmounted=\n", d.fs), 0
	case strings.Contains(script, "mkfs.ext4"):
		d.fs = "ext4"
	case strings.Contains(script, "vgcreate"):
		d.vg = true
	case strings.Contains(script, "vg_extent_size"):
		if !d.vg {
			return "volume group data doesn't exist on this host", 1
		}
		out := "extent=4194304\nvgsize=1069547520\n"
		if d.lv {
			out += "exists=1\nsize=536870912\n"
		}
		return out, 0
	case strings.Contains(script, "lvcreate"):
		d.lv = true
	case strings.Contains(script, "echo exists=1"):
		if d.vg {
			return "exists=1\n", 0
		}
	case strings.Contains(script, "unit B print"):
		out := "BYT;\n/dev/vdb:1073741824B:virtblk:512:512:gpt:Virtio Block Device:;\n"
		if d.part {
			out += "1:1048576B:1073724927B:1072676352B::primary:lvm;\n"
		}
		return out + "--\n", 0
	case strings.Contains(script, "mkpart primary"):
		d.part = true
	}
	return "", 0
}

// Each storage step makes what the disk lacks, then reads back in sync.
func TestStorageStepsMakeWhatTheDiskLacks(t *testing.T) {
	d := &unitDisk{}
	ssh := unitHost(t, d.answer)
	strs := func(s ...string) cty.Value {
		vs := make([]cty.Value, len(s))
		for i, v := range s {
			vs[i] = cty.StringVal(v)
		}
		return cty.ListVal(vs)
	}
	for _, step := range []struct {
		typeName string
		attrs    map[string]cty.Value
	}{
		{"conn3x_partition", map[string]cty.Value{"device": cty.StringVal("/dev/vdb"), "number": cty.NumberIntVal(1), "start": cty.StringVal("1MiB"), "end": cty.StringVal("100%"), "flags": strs("lvm")}},
		{"conn3x_lvm_volume_group", map[string]cty.Value{"name": cty.StringVal("data"), "pvs": strs("/dev/vdb1")}},
		{"conn3x_lvm_logical_volume", map[string]cty.Value{"vg": cty.StringVal("data"), "name": cty.StringVal("www"), "size": cty.StringVal("512M")}},
		{"conn3x_filesystem", map[string]cty.Value{"device": cty.StringVal("/dev/data/www"), "type": cty.StringVal("ext4")}},
	} {
		state, err := unitCreate(t, step.typeName, eosStep(step.typeName, step.attrs, ssh))
		if err != nil {
			t.Fatalf("%s: %v", step.typeName, err)
		}
		got, err := unitRead(step.typeName, state)
		if err != nil || !got.GetAttr("in_sync").True() {
			t.Errorf("%s: read back in_sync = %#v, %v", step.typeName, got.GetAttr("in_sync"), err)
		}
	}
	if !d.part || !d.vg || !d.lv || d.fs != "ext4" {
		t.Errorf("disk after the steps: %+v", d)
	}
}

// A host error reaches the step's diagnostics, on read and on apply.
func TestStorageStepsReportHostErrors(t *testing.T) {
	d := &unitDisk{gone: true}
	ssh := unitHost(t, d.answer)
	for typeName, attrs := range map[string]map[string]cty.Value{
		"conn3x_partition":          {"device": cty.StringVal("/dev/vdb"), "number": cty.NumberIntVal(1), "start": cty.StringVal("1MiB"), "end": cty.StringVal("100%")},
		"conn3x_lvm_volume_group":   {"name": cty.StringVal("data"), "pvs": cty.ListVal([]cty.Value{cty.StringVal("/dev/vdb")})},
		"conn3x_lvm_logical_volume": {"vg": cty.StringVal("data"), "name": cty.StringVal("www"), "size": cty.StringVal("512M")},
		"conn3x_filesystem":         {"device": cty.StringVal("/dev/vdb"), "type": cty.StringVal("ext4")},
	} {
		cfg := eosStep(typeName, attrs, ssh)
		if _, err := unitCreate(t, typeName, cfg); err == nil {
			t.Errorf("%s: apply on a missing device succeeded", typeName)
		}
		vals := cfg.AsValueMap()
		vals["id"], vals["in_sync"] = cty.StringVal("x"), cty.True
		if _, err := unitRead(typeName, cty.ObjectVal(vals)); err == nil {
			t.Errorf("%s: read of a missing device succeeded", typeName)
		}
	}
}

// force warns at every plan, since it lets the step destroy data.
func TestStorageForceWarns(t *testing.T) {
	p, _ := New()
	for typeName, attrs := range map[string]map[string]cty.Value{
		"conn3x_lvm_volume_group":   {"name": cty.StringVal("data"), "pvs": cty.ListVal([]cty.Value{cty.StringVal("/dev/vdb")})},
		"conn3x_lvm_logical_volume": {"vg": cty.StringVal("data"), "name": cty.StringVal("www"), "size": cty.StringVal("512M")},
		"conn3x_filesystem":         {"device": cty.StringVal("/dev/vdb"), "type": cty.StringVal("ext4")},
	} {
		attrs["force"] = cty.True
		resp := p.ValidateResourceConfig(ctx, providers.ValidateResourceConfigRequest{TypeName: typeName, Config: eosStep(typeName, attrs, nil)})
		if resp.Diagnostics.HasErrors() || len(resp.Diagnostics) != 1 || !strings.Contains(resp.Diagnostics[0].Description().Summary, "force") {
			t.Errorf("%s with force: %v", typeName, resp.Diagnostics)
		}
		attrs["force"] = cty.False
		if resp := p.ValidateResourceConfig(ctx, providers.ValidateResourceConfigRequest{TypeName: typeName, Config: eosStep(typeName, attrs, nil)}); len(resp.Diagnostics) != 0 {
			t.Errorf("%s without force: %v", typeName, resp.Diagnostics)
		}
	}
}

// A file system that grows goes stale when an earlier step changes, since
// that step may grow the device after the refresh read it.
func TestFilesystemResizePlansStaleAfterAnEarlierChange(t *testing.T) {
	r := resourceTypes["conn3x_filesystem"]
	prior := objFor(r.schema(), map[string]cty.Value{
		"id": cty.StringVal("203.0.113.10:filesystem:/dev/vdb"), "device": cty.StringVal("/dev/vdb"), "type": cty.StringVal("xfs"),
		"resize": cty.True, "in_sync": cty.True, "earlier_revisions": cty.ListVal([]cty.Value{cty.StringVal("r1")}),
	})
	plan := func(earlier cty.Value) cty.Value {
		vals := prior.AsValueMap()
		vals["earlier_revisions"] = earlier
		next := cty.ObjectVal(vals)
		return r.plan(providers.PlanResourceChangeRequest{PriorState: prior, ProposedNewState: next, Config: next}).PlannedState
	}
	if got := plan(prior.GetAttr("earlier_revisions")).GetAttr("in_sync"); !got.IsKnown() || !got.True() {
		t.Errorf("nothing earlier changed: in_sync = %#v", got)
	}
	if got := plan(cty.ListVal([]cty.Value{cty.StringVal("r2")})).GetAttr("in_sync"); got.IsKnown() {
		t.Errorf("an earlier step changed: in_sync = %#v", got)
	}
	if got := plan(cty.UnknownVal(cty.List(cty.String))).GetAttr("in_sync"); got.IsKnown() {
		t.Errorf("an earlier revision unknown: in_sync = %#v", got)
	}
}
