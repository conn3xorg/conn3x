// Copyright (c) The Conn3x Authors
// SPDX-License-Identifier: MPL-2.0

// Package agentpb is the wire protocol between conn3x and its host agent:
// the messages in agent.proto, encoded with protowire so the agent carries
// no protobuf runtime, and the frames they travel in.
package agentpb

import (
	"errors"
	"fmt"
	"math"

	"google.golang.org/protobuf/encoding/protowire"
)

// Envelope carries one message. Exactly one of its bodies is set.
type Envelope struct {
	ID     uint64
	Hello  *Hello
	Exec   *ExecRequest
	Result *ExecResponse
	Cancel *Cancel
	Error  *Error
}

// Hello is the first frame the agent sends.
type Hello struct {
	Version uint32
}

// ExecRequest runs Cmd with /bin/sh in the C locale, feeding it Stdin.
type ExecRequest struct {
	Cmd   string
	Stdin []byte
}

// ExecResponse is the outcome of an ExecRequest.
type ExecResponse struct {
	Stdout   []byte
	Stderr   []byte
	ExitCode int32
}

// Cancel kills the request with the same ID, and everything it started.
type Cancel struct{}

// Error answers a request the agent could not carry out.
type Error struct {
	Code    Code
	Message string
}

// Code says why a request failed.
type Code int32

const (
	CodeUnspecified Code = iota
	CodeUnsupported
	CodeInternal
	CodeCanceled
)

func (c Code) String() string {
	switch c {
	case CodeUnsupported:
		return "unsupported"
	case CodeInternal:
		return "internal error"
	case CodeCanceled:
		return "canceled"
	}
	return "unknown error"
}

// Field numbers, as in agent.proto.
const (
	fieldID     = 1
	fieldHello  = 2
	fieldExec   = 3
	fieldResult = 4
	fieldCancel = 5
	fieldError  = 6
)

// Size is the encoded length of e.
func (e *Envelope) Size() int {
	n := sizeVarint(fieldID, e.ID)
	if num, body := e.body(); body != nil {
		n += protowire.SizeTag(num) + protowire.SizeBytes(body.size())
	}
	return n
}

// Append encodes e onto b.
func (e *Envelope) Append(b []byte) []byte {
	b = appendVarint(b, fieldID, e.ID)
	if num, body := e.body(); body != nil {
		b = protowire.AppendTag(b, num, protowire.BytesType)
		b = protowire.AppendVarint(b, uint64(body.size()))
		b = body.encode(b)
	}
	return b
}

// message is one of the bodies an Envelope can carry.
type message interface {
	size() int
	encode(b []byte) []byte
}

// body returns the body that is set and its field number, or nil.
func (e *Envelope) body() (protowire.Number, message) {
	switch {
	case e.Hello != nil:
		return fieldHello, e.Hello
	case e.Exec != nil:
		return fieldExec, e.Exec
	case e.Result != nil:
		return fieldResult, e.Result
	case e.Cancel != nil:
		return fieldCancel, e.Cancel
	case e.Error != nil:
		return fieldError, e.Error
	}
	return 0, nil
}

// Unmarshal decodes b into e. Byte fields share b's memory. Unknown fields
// are skipped, so newer peers can add them; a known field with the wrong
// wire type or an out-of-range value, or a second body, is an error.
func (e *Envelope) Unmarshal(b []byte) error {
	*e = Envelope{}
	return fields(b, func(f field) error {
		if f.num >= fieldHello && f.num <= fieldError {
			if num, _ := e.body(); num != 0 {
				return errors.New("more than one body in an agent message")
			}
		}
		var err error
		switch f.num {
		case fieldID:
			e.ID, err = f.uint(math.MaxUint64)
		case fieldHello:
			e.Hello = &Hello{}
			err = f.message(func(f field) error {
				if f.num == 1 {
					x, err := f.uint(math.MaxUint32)
					e.Hello.Version = uint32(x)
					return err
				}
				return nil
			})
		case fieldExec:
			e.Exec = &ExecRequest{}
			err = f.message(func(f field) (err error) {
				switch f.num {
				case 1:
					var v []byte
					v, err = f.bytes()
					e.Exec.Cmd = string(v)
				case 2:
					e.Exec.Stdin, err = f.bytes()
				}
				return err
			})
		case fieldResult:
			e.Result = &ExecResponse{}
			err = f.message(func(f field) (err error) {
				switch f.num {
				case 1:
					e.Result.Stdout, err = f.bytes()
				case 2:
					e.Result.Stderr, err = f.bytes()
				case 3:
					e.Result.ExitCode, err = f.int32()
				}
				return err
			})
		case fieldCancel:
			e.Cancel = &Cancel{}
			err = f.message(func(field) error { return nil })
		case fieldError:
			e.Error = &Error{}
			err = f.message(func(f field) (err error) {
				switch f.num {
				case 1:
					var x uint64
					x, err = f.uint(math.MaxInt32)
					e.Error.Code = Code(x)
				case 2:
					var v []byte
					v, err = f.bytes()
					e.Error.Message = string(v)
				}
				return err
			})
		}
		return err
	})
}

// field is one decoded field: x holds a varint's value, v a
// length-delimited field's bytes.
type field struct {
	num protowire.Number
	typ protowire.Type
	x   uint64
	v   []byte
}

func (f field) uint(max uint64) (uint64, error) {
	if f.typ != protowire.VarintType {
		return 0, fmt.Errorf("agent message field %d: wire type %d, want a varint", f.num, f.typ)
	}
	if f.x > max {
		return 0, fmt.Errorf("agent message field %d: %d is out of range", f.num, f.x)
	}
	return f.x, nil
}

// int32 reads a sign-extended int32, as protobuf encodes one.
func (f field) int32() (int32, error) {
	x, err := f.uint(math.MaxUint64)
	if err != nil {
		return 0, err
	}
	if int64(x) < math.MinInt32 || int64(x) > math.MaxInt32 {
		return 0, fmt.Errorf("agent message field %d: %d is out of range", f.num, int64(x))
	}
	return int32(x), nil
}

func (f field) bytes() ([]byte, error) {
	if f.typ != protowire.BytesType {
		return nil, fmt.Errorf("agent message field %d: wire type %d, want bytes", f.num, f.typ)
	}
	return f.v, nil
}

// message decodes a nested message's fields with decode.
func (f field) message(decode func(field) error) error {
	v, err := f.bytes()
	if err != nil {
		return err
	}
	return fields(v, decode)
}

// fields calls f for each field in b.
func fields(b []byte, f func(field) error) error {
	for len(b) > 0 {
		num, typ, n := protowire.ConsumeTag(b)
		if n < 0 {
			return protowire.ParseError(n)
		}
		b = b[n:]
		fl := field{num: num, typ: typ}
		switch typ {
		case protowire.VarintType:
			fl.x, n = protowire.ConsumeVarint(b)
		case protowire.BytesType:
			fl.v, n = protowire.ConsumeBytes(b)
		default:
			n = protowire.ConsumeFieldValue(num, typ, b)
		}
		if n < 0 {
			return protowire.ParseError(n)
		}
		b = b[n:]
		if err := f(fl); err != nil {
			return err
		}
	}
	return nil
}

func (h *Hello) size() int { return sizeVarint(1, uint64(h.Version)) }

func (h *Hello) encode(b []byte) []byte {
	return appendVarint(b, 1, uint64(h.Version))
}

func (r *ExecRequest) size() int {
	return sizeBytes(1, len(r.Cmd)) + sizeBytes(2, len(r.Stdin))
}

func (r *ExecRequest) encode(b []byte) []byte {
	b = appendBytes(b, 1, []byte(r.Cmd))
	return appendBytes(b, 2, r.Stdin)
}

// int32 is sign-extended on the wire, as protobuf does.
func (r *ExecResponse) size() int {
	return sizeBytes(1, len(r.Stdout)) + sizeBytes(2, len(r.Stderr)) + sizeVarint(3, uint64(int64(r.ExitCode)))
}

func (r *ExecResponse) encode(b []byte) []byte {
	b = appendBytes(b, 1, r.Stdout)
	b = appendBytes(b, 2, r.Stderr)
	return appendVarint(b, 3, uint64(int64(r.ExitCode)))
}

func (*Cancel) size() int              { return 0 }
func (*Cancel) encode(b []byte) []byte { return b }

func (e *Error) size() int {
	return sizeVarint(1, uint64(e.Code)) + sizeBytes(2, len(e.Message))
}

func (e *Error) encode(b []byte) []byte {
	b = appendVarint(b, 1, uint64(e.Code))
	return appendBytes(b, 2, []byte(e.Message))
}

// The helpers below leave out zero values, as proto3 does.

func sizeVarint(num protowire.Number, x uint64) int {
	if x == 0 {
		return 0
	}
	return protowire.SizeTag(num) + protowire.SizeVarint(x)
}

func sizeBytes(num protowire.Number, n int) int {
	if n == 0 {
		return 0
	}
	return protowire.SizeTag(num) + protowire.SizeBytes(n)
}

func appendVarint(b []byte, num protowire.Number, x uint64) []byte {
	if x == 0 {
		return b
	}
	b = protowire.AppendTag(b, num, protowire.VarintType)
	return protowire.AppendVarint(b, x)
}

func appendBytes(b []byte, num protowire.Number, v []byte) []byte {
	if len(v) == 0 {
		return b
	}
	b = protowire.AppendTag(b, num, protowire.BytesType)
	return protowire.AppendBytes(b, v)
}
