// Copyright (c) The Conn3x Authors
// SPDX-License-Identifier: MPL-2.0

package agentpb

import (
	"encoding/binary"
	"errors"
	"fmt"
	"io"
)

// ProtocolVersion is what the agent says in Hello. Both sides must agree.
const ProtocolVersion = 1

// MaxFrame is the largest Envelope either side sends or accepts.
const MaxFrame = 256 << 20

// ErrFrameTooLarge is returned for an Envelope bigger than MaxFrame.
var ErrFrameTooLarge = errors.New("agent frame too large")

// WriteFrame sends e as one write: its length, four bytes big-endian, then
// the encoded Envelope.
func WriteFrame(w io.Writer, e *Envelope) error {
	n := e.Size()
	if n > MaxFrame {
		return fmt.Errorf("%w: %d bytes, the limit is %d", ErrFrameTooLarge, n, MaxFrame)
	}
	b := binary.BigEndian.AppendUint32(make([]byte, 0, 4+n), uint32(n))
	_, err := w.Write(e.Append(b))
	return err
}

// ReadFrame reads one Envelope. It returns io.EOF only when r ends cleanly
// between frames, and refuses a length over MaxFrame before allocating it.
func ReadFrame(r io.Reader) (*Envelope, error) {
	var header [4]byte
	if _, err := io.ReadFull(r, header[:]); err != nil {
		return nil, err
	}
	n := binary.BigEndian.Uint32(header[:])
	if n > MaxFrame {
		return nil, fmt.Errorf("%w: %d bytes, the limit is %d", ErrFrameTooLarge, n, MaxFrame)
	}
	b := make([]byte, n)
	if _, err := io.ReadFull(r, b); err != nil {
		if err == io.EOF {
			err = io.ErrUnexpectedEOF
		}
		return nil, err
	}
	e := &Envelope{}
	if err := e.Unmarshal(b); err != nil {
		return nil, fmt.Errorf("agent frame: %w", err)
	}
	return e, nil
}
