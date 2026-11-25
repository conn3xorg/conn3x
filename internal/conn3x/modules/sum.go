// Copyright (c) The Conn3x Authors
// SPDX-License-Identifier: MPL-2.0

package modules

// Sum256 defines sum256, which prints the SHA-256 of the file $1 names, or
// nothing when it can't be opened. It hashes stdin, because GNU sha256sum
// puts a "\" before the hash when the file's name holds a backslash or a
// newline. Opening a FIFO blocks, so check [ -f "$1" ] first.
const Sum256 = `sum256() { if command -v sha256sum >/dev/null 2>&1; then sha256sum; else shasum -a 256; fi < "$1" | cut -d' ' -f1; }
`
