// Copyright (c) The Conn3x Authors
// SPDX-License-Identifier: MPL-2.0

// Package version reports the Conn3x release and the OpenTofu release
// it is built on.
package version

import (
	_ "embed"
	"strings"
)

// Version is the Conn3x release, set at build time with
// -ldflags "-X github.com/opentofu/opentofu/internal/conn3x/version.Version=...".
var Version = "0.0.0-dev"

//go:embed UPSTREAM
var upstream string

// String returns the human-readable version line.
func String() string {
	return "Conn3x v" + Version + " (built on OpenTofu " + strings.TrimSpace(upstream) + ")"
}
