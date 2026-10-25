// Copyright (c) The Conn3x Authors
// SPDX-License-Identifier: MPL-2.0

package agentpb

import (
	"bytes"
	"encoding/binary"
	"errors"
	"io"
	"reflect"
	"testing"
)

func TestFrameRoundTrip(t *testing.T) {
	for _, e := range []*Envelope{
		{Hello: &Hello{Version: ProtocolVersion}},
		{ID: 1, Exec: &ExecRequest{}},
		{ID: 2, Exec: &ExecRequest{Cmd: "cat", Stdin: []byte("a\x00b\xff")}},
		{ID: 3, Result: &ExecResponse{Stdout: []byte("out"), Stderr: []byte("err"), ExitCode: 42}},
		{ID: 4, Result: &ExecResponse{ExitCode: -1}},
		{ID: 1 << 40, Cancel: &Cancel{}},
		{ID: 6, Error: &Error{Code: CodeCanceled, Message: "canceled"}},
	} {
		var buf bytes.Buffer
		if err := WriteFrame(&buf, e); err != nil {
			t.Fatal(err)
		}
		got, err := ReadFrame(&buf)
		if err != nil {
			t.Fatalf("ReadFrame(%+v): %v", e, err)
		}
		if !reflect.DeepEqual(got, e) {
			t.Errorf("round trip: got %+v, want %+v", got, e)
		}
		if _, err := ReadFrame(&buf); err != io.EOF {
			t.Errorf("after the last frame: err = %v, want io.EOF", err)
		}
	}

	// The bytes agent.proto defines, so the codec can't drift from it:
	// id = 1, exec_request = 3 { cmd = 1 "true" }.
	var buf bytes.Buffer
	if err := WriteFrame(&buf, &Envelope{ID: 1, Exec: &ExecRequest{Cmd: "true"}}); err != nil {
		t.Fatal(err)
	}
	want := []byte{0, 0, 0, 10, 0x08, 0x01, 0x1a, 0x06, 0x0a, 0x04, 't', 'r', 'u', 'e'}
	if !bytes.Equal(buf.Bytes(), want) {
		t.Errorf("wire bytes = % x, want % x", buf.Bytes(), want)
	}
}

func TestReadFrameRejectsOversize(t *testing.T) {
	var header [4]byte
	binary.BigEndian.PutUint32(header[:], MaxFrame+1)
	// Only the header exists; reading would block or fail, so a size
	// error proves the length was checked before anything was allocated.
	_, err := ReadFrame(bytes.NewReader(header[:]))
	if !errors.Is(err, ErrFrameTooLarge) {
		t.Fatalf("err = %v, want ErrFrameTooLarge", err)
	}

	big := &Envelope{Result: &ExecResponse{Stdout: make([]byte, MaxFrame)}}
	if err := WriteFrame(io.Discard, big); !errors.Is(err, ErrFrameTooLarge) {
		t.Fatalf("WriteFrame: err = %v, want ErrFrameTooLarge", err)
	}
}

func TestReadFrameTruncated(t *testing.T) {
	var buf bytes.Buffer
	if err := WriteFrame(&buf, &Envelope{ID: 9, Exec: &ExecRequest{Cmd: "echo hi"}}); err != nil {
		t.Fatal(err)
	}
	full := buf.Bytes()
	for _, n := range []int{1, 3, 4, len(full) - 1} {
		if _, err := ReadFrame(bytes.NewReader(full[:n])); err != io.ErrUnexpectedEOF {
			t.Errorf("%d of %d bytes: err = %v, want io.ErrUnexpectedEOF", n, len(full), err)
		}
	}

	// A frame whose body is not a valid message.
	bad := []byte{0, 0, 0, 2, 0x1a, 0x05}
	if _, err := ReadFrame(bytes.NewReader(bad)); err == nil || err == io.ErrUnexpectedEOF {
		t.Errorf("malformed body: err = %v, want a parse error", err)
	}
}
