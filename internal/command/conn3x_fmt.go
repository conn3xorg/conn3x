// Copyright (c) The Conn3x Authors
// SPDX-License-Identifier: MPL-2.0

package command

// Circuits are configuration too, so fmt formats them with the rest.
func init() { fmtSupportedExts = append(fmtSupportedExts, ".circuit.hcl") }
