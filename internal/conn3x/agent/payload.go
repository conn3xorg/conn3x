// Copyright (c) The Conn3x Authors
// SPDX-License-Identifier: MPL-2.0

package agent

import (
	"bytes"
	"compress/gzip"
	"crypto/sha256"
	"embed"
	"errors"
	"fmt"
	"io"
	"io/fs"
)

// ErrUnavailable is wrapped when the agent can't run on a host, or this
// build has none to offer. Commands then go through the shell.
var ErrUnavailable = errors.New("the conn3x agent is unavailable")

//go:embed payload
var embedded embed.FS

// payloadFS is where Embedded looks; tests swap it.
var payloadFS fs.FS = embedded

// Embedded returns the gzipped agent for linux/arch that scripts/build-agent.sh
// put in this build, and the sha256 of the binary inside it.
func Embedded(arch string) (gz []byte, sum [32]byte, err error) {
	gz, err = fs.ReadFile(payloadFS, "payload/conn3x-agent-linux-"+arch+".gz")
	if err != nil {
		return nil, sum, fmt.Errorf("%w: this build has no agent for linux/%s", ErrUnavailable, arch)
	}
	r, err := gzip.NewReader(bytes.NewReader(gz))
	if err != nil {
		return nil, sum, fmt.Errorf("the embedded agent for linux/%s: %w", arch, err)
	}
	h := sha256.New()
	if _, err := io.Copy(h, r); err != nil {
		return nil, sum, fmt.Errorf("the embedded agent for linux/%s: %w", arch, err)
	}
	copy(sum[:], h.Sum(nil))
	return gz, sum, nil
}
