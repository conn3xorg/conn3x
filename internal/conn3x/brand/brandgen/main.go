// Copyright (c) The Conn3x Authors
// SPDX-License-Identifier: MPL-2.0

// Command brandgen writes the build overlay that makes conn3x speak as
// Conn3x, and prints its path.
//
//	go run ./internal/conn3x/brand/brandgen -out DIR
package main

import (
	"flag"
	"fmt"
	"os"

	"github.com/opentofu/opentofu/internal/conn3x/brand"
)

func main() {
	root := flag.String("root", ".", "repository root")
	out := flag.String("out", "", "directory for the rewritten sources and overlay.json")
	flag.Parse()
	if *out == "" {
		fmt.Fprintln(os.Stderr, "brandgen: -out is required")
		os.Exit(2)
	}
	overlay, err := brand.Generate(*root, *out)
	if err != nil {
		fmt.Fprintln(os.Stderr, "brandgen:", err)
		os.Exit(1)
	}
	fmt.Println(overlay)
}
