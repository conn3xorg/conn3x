// Copyright (c) The Conn3x Authors
// SPDX-License-Identifier: MPL-2.0

package agentpb

import (
	"reflect"
	"testing"
)

func TestUnmarshalSkipsUnknownFields(t *testing.T) {
	b := []byte{
		0x08, 0x07, // id = 7
		0x78, 0x05, // field 15, varint
		0x82, 0x01, 0x02, 'h', 'i', // field 16, bytes
		0x1a, 0x09, // exec_request
		0x0a, 0x02, 'l', 's', // cmd = "ls"
		0x4d, 0x01, 0x02, 0x03, 0x04, // field 9, fixed32
	}
	var e Envelope
	if err := e.Unmarshal(b); err != nil {
		t.Fatal(err)
	}
	if want := (Envelope{ID: 7, Exec: &ExecRequest{Cmd: "ls"}}); !reflect.DeepEqual(e, want) {
		t.Fatalf("got %+v, want %+v", e, want)
	}
}

// malformed are envelopes that decode as protobuf but break agent.proto.
var malformed = map[string][]byte{
	"id as bytes":           {0x0a, 0x00},
	"hello as varint":       {0x10, 0x01},
	"two bodies":            {0x12, 0x00, 0x2a, 0x00},
	"cmd as varint":         {0x1a, 0x02, 0x08, 0x01},
	"version over uint32":   {0x12, 0x06, 0x08, 0x80, 0x80, 0x80, 0x80, 0x10},
	"code over int32":       {0x32, 0x06, 0x08, 0x80, 0x80, 0x80, 0x80, 0x08},
	"exit code over int32":  {0x22, 0x06, 0x18, 0x80, 0x80, 0x80, 0x80, 0x08},
	"truncated body":        {0x1a, 0x05, 0x0a},
	"truncated nested cmd":  {0x1a, 0x02, 0x0a, 0x05},
	"invalid wire type (7)": {0x0f},
	"mode over uint32":      {0x42, 0x06, 0x18, 0x80, 0x80, 0x80, 0x80, 0x10},
	"exists as bytes":       {0x42, 0x02, 0x0a, 0x00},
	"prop as varint":        {0x52, 0x02, 0x08, 0x01},
	"prop key as varint":    {0x52, 0x04, 0x0a, 0x02, 0x08, 0x01},
}

func TestUnmarshalRejectsMalformed(t *testing.T) {
	for name, b := range malformed {
		var e Envelope
		if err := e.Unmarshal(b); err == nil {
			t.Errorf("%s: decoded as %+v, want an error", name, e)
		}
	}
}

func FuzzEnvelopeUnmarshal(f *testing.F) {
	for _, e := range []*Envelope{
		{Hello: &Hello{Version: ProtocolVersion}},
		{ID: 2, Exec: &ExecRequest{Cmd: "cat", Stdin: []byte("a\x00b")}},
		{ID: 3, Result: &ExecResponse{Stdout: []byte("out"), ExitCode: -1}},
		{ID: 4, Cancel: &Cancel{}},
		{ID: 5, Error: &Error{Code: CodeInternal, Message: "x"}},
		{ID: 6, ReadFile: &ReadFileRequest{Path: "/x"}},
		{ID: 7, File: &FileStat{Exists: true, Mode: 0o644, Content: []byte("x")}},
		{ID: 8, ReadUnit: &ReadUnitRequest{Unit: "a.service"}},
		{ID: 9, Unit: &UnitProps{Props: map[string]string{"k": "v"}}},
	} {
		f.Add(e.Append(nil))
	}
	for _, b := range malformed {
		f.Add(b)
	}
	f.Fuzz(func(t *testing.T, b []byte) {
		var e Envelope
		if e.Unmarshal(b) != nil {
			return
		}
		// Whatever decodes must encode to its stated size and decode again.
		out := e.Append(nil)
		if len(out) != e.Size() {
			t.Fatalf("Append wrote %d bytes, Size says %d", len(out), e.Size())
		}
		var again Envelope
		if err := again.Unmarshal(out); err != nil {
			t.Fatalf("re-encoding %+v gave undecodable bytes: %v", e, err)
		}
	})
}
