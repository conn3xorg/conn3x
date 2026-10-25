// Copyright (c) The Conn3x Authors
// SPDX-License-Identifier: MPL-2.0

package brand

import (
	"fmt"
	"go/format"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
)

// prunedBackends are the remote-state backends the conn3x build leaves out,
// by name and import alias: Tencent COS and Alibaba OSS, each of which
// carries its cloud's SDK. Kubernetes is heavier but widely used, so it stays.
var prunedBackends = map[string]string{
	"cos": "backendCos",
	"oss": "backendOSS",
}

const backendInit = "internal/backend/init/init.go"

// pruneBackends drops the pruned backends from init.go and lists them in
// RemovedBackends, so a configuration using one gets a clear error. It fails
// if upstream changed the file so a backend is no longer where it expected.
func pruneBackends(src []byte) ([]byte, error) {
	lines := strings.Split(string(src), "\n")
	names := make([]string, 0, len(prunedBackends))
	for name := range prunedBackends {
		names = append(names, name)
	}
	sort.Strings(names)
	for _, name := range names {
		alias := regexp.MustCompile(`\b` + prunedBackends[name] + `\b`)
		kept, dropped := lines[:0:0], 0
		for _, l := range lines {
			if alias.MatchString(l) {
				dropped++
				continue
			}
			kept = append(kept, l)
		}
		if dropped != 2 { // its import and its table entry
			return nil, fmt.Errorf("%s: expected an import and a table entry for %s, found %d lines", backendInit, prunedBackends[name], dropped)
		}
		lines = kept
	}
	at := -1
	for i, l := range lines {
		if strings.Contains(l, "RemovedBackends = map[string]string{") {
			at = i + 1
		}
	}
	if at < 0 {
		return nil, fmt.Errorf("%s: RemovedBackends not found", backendInit)
	}
	var removed []string
	for _, name := range names {
		removed = append(removed, fmt.Sprintf("\t\t%q: `The %q backend is not included in Conn3x, to keep the binary small. Move the state to another backend first, for example with OpenTofu's init -migrate-state.`,", name, name))
	}
	lines = append(lines[:at], append(removed, lines[at:]...)...)
	return format.Source([]byte(strings.Join(lines, "\n")))
}

// prune applies pruneBackends to init.go, starting from its branded copy
// when there is one, and records the result in the overlay.
func prune(root, outDir string, replace map[string]string) error {
	orig := filepath.Join(root, filepath.FromSlash(backendInit))
	from := orig
	if branded, ok := replace[orig]; ok {
		from = branded
	}
	src, err := os.ReadFile(from)
	if os.IsNotExist(err) {
		return nil // a tree without OpenTofu's backends has nothing to prune
	}
	if err != nil {
		return err
	}
	out, err := pruneBackends(src)
	if err != nil {
		return err
	}
	dest := filepath.Join(outDir, filepath.FromSlash(backendInit))
	if err := os.MkdirAll(filepath.Dir(dest), 0o755); err != nil {
		return err
	}
	replace[orig] = dest
	return os.WriteFile(dest, out, 0o644)
}
