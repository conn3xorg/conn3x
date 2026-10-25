// Copyright (c) The Conn3x Authors
// SPDX-License-Identifier: MPL-2.0

// Package agentpb is the wire protocol between conn3x and its host agent:
// the messages in agent.proto, encoded with protowire so the agent carries
// no protobuf runtime, and the frames they travel in.
package agentpb

import (
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
// are skipped, so newer peers can add them.
func (e *Envelope) Unmarshal(b []byte) error {
	*e = Envelope{}
	return fields(b, func(num protowire.Number, x uint64, v []byte) error {
		switch num {
		case fieldID:
			e.ID = x
		case fieldHello:
			e.Hello = &Hello{}
			return fields(v, func(num protowire.Number, x uint64, _ []byte) error {
				if num == 1 {
					e.Hello.Version = uint32(x)
				}
				return nil
			})
		case fieldExec:
			e.Exec = &ExecRequest{}
			return fields(v, func(num protowire.Number, _ uint64, v []byte) error {
				switch num {
				case 1:
					e.Exec.Cmd = string(v)
				case 2:
					e.Exec.Stdin = v
				}
				return nil
			})
		case fieldResult:
			e.Result = &ExecResponse{}
			return fields(v, func(num protowire.Number, x uint64, v []byte) error {
				switch num {
				case 1:
					e.Result.Stdout = v
				case 2:
					e.Result.Stderr = v
				case 3:
					e.Result.ExitCode = int32(x)
				}
				return nil
			})
		case fieldCancel:
			e.Cancel = &Cancel{}
		case fieldError:
			e.Error = &Error{}
			return fields(v, func(num protowire.Number, x uint64, v []byte) error {
				switch num {
				case 1:
					e.Error.Code = Code(x)
				case 2:
					e.Error.Message = string(v)
				}
				return nil
			})
		}
		return nil
	})
}

// fields calls f for each varint (x) and length-delimited (v) field in b
// and skips the rest.
func fields(b []byte, f func(num protowire.Number, x uint64, v []byte) error) error {
	for len(b) > 0 {
		num, typ, n := protowire.ConsumeTag(b)
		if n < 0 {
			return protowire.ParseError(n)
		}
		b = b[n:]
		var x uint64
		var v []byte
		switch typ {
		case protowire.VarintType:
			x, n = protowire.ConsumeVarint(b)
		case protowire.BytesType:
			v, n = protowire.ConsumeBytes(b)
		default:
			n = protowire.ConsumeFieldValue(num, typ, b)
		}
		if n < 0 {
			return protowire.ParseError(n)
		}
		b = b[n:]
		if typ == protowire.VarintType || typ == protowire.BytesType {
			if err := f(num, x, v); err != nil {
				return err
			}
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
