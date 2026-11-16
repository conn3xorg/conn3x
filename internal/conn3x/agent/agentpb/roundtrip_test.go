// Copyright (c) The Conn3x Authors
// SPDX-License-Identifier: MPL-2.0

package agentpb

import (
	"reflect"
	"testing"
)

// Every body survives an encode and a decode, and Size is what Append writes.
func TestEnvelopeRoundTrip(t *testing.T) {
	for _, e := range []Envelope{
		{ID: 1},
		{ID: 2, Hello: &Hello{Version: 3}},
		{ID: 3, Exec: &ExecRequest{Cmd: "ls", Stdin: []byte("in")}},
		{ID: 4, Result: &ExecResponse{Stdout: []byte("o"), Stderr: []byte("e"), ExitCode: -2}},
		{ID: 5, Cancel: &Cancel{}},
		{ID: 6, Error: &Error{Code: CodeCanceled, Message: "stop"}},
		{ID: 7, ReadFile: &ReadFileRequest{Path: "/etc/hosts"}},
		{ID: 8, File: &FileStat{Exists: true, Regular: true, Mode: 0o640, Owner: "root", Group: "adm", Content: []byte("x")}},
		{ID: 9, ReadUnit: &ReadUnitRequest{Unit: "sshd.service"}},
		{ID: 10, Unit: &UnitProps{Props: map[string]string{"ActiveState": "active", "Id": "sshd.service"}}},
	} {
		b := e.Append(nil)
		if len(b) != e.Size() {
			t.Errorf("%+v: Size %d, Append wrote %d", e, e.Size(), len(b))
		}
		var got Envelope
		if err := got.Unmarshal(b); err != nil {
			t.Fatalf("%+v: %v", e, err)
		}
		if !reflect.DeepEqual(got, e) {
			t.Errorf("got %+v, want %+v", got, e)
		}
	}
}

// Fields a nested message doesn't know are skipped, as at the top level.
func TestNestedUnknownFieldsSkipped(t *testing.T) {
	unknown := []byte{0x78, 0x01} // field 15, varint
	for num, want := range map[byte]Envelope{
		0x12: {Hello: &Hello{}},
		0x3a: {ReadFile: &ReadFileRequest{}},
		0x4a: {ReadUnit: &ReadUnitRequest{}},
		0x52: {Unit: &UnitProps{}},
		0x42: {File: &FileStat{}},
		0x32: {Error: &Error{}},
		0x22: {Result: &ExecResponse{}},
		0x1a: {Exec: &ExecRequest{}},
	} {
		var e Envelope
		if err := e.Unmarshal(append([]byte{num, byte(len(unknown))}, unknown...)); err != nil || !reflect.DeepEqual(e, want) {
			t.Errorf("tag %#x: got %+v, %v", num, e, err)
		}
	}
	// A map entry without a value has an empty one.
	var e Envelope
	if err := e.Unmarshal([]byte{0x52, 0x05, 0x0a, 0x03, 0x0a, 0x01, 'k'}); err != nil || e.Unit.Props["k"] != "" || len(e.Unit.Props) != 1 {
		t.Errorf("entry without a value: %+v, %v", e.Unit, err)
	}
	// Field number 0 isn't a tag.
	if err := e.Unmarshal([]byte{0x00}); err == nil {
		t.Error("decoded field 0")
	}
}

func TestCodeString(t *testing.T) {
	for c, want := range map[Code]string{
		CodeUnsupported: "unsupported", CodeInternal: "internal error", CodeCanceled: "canceled",
		CodeUnspecified: "unknown error", Code(99): "unknown error",
	} {
		if got := c.String(); got != want {
			t.Errorf("%d: %q, want %q", c, got, want)
		}
	}
}
