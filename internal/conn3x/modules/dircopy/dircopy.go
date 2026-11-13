// Copyright (c) The Conn3x Authors
// SPDX-License-Identifier: MPL-2.0

// Package dircopy copies a directory from the controller to a host, file by
// file, as ansible.posix.synchronize does: only the files whose content,
// mode or owner differ are written, each the way the file module writes
// one, and with Delete the files the source doesn't have are removed.
package dircopy

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io/fs"
	"os"
	"path"
	"path/filepath"
	"slices"
	"strings"

	"github.com/opentofu/opentofu/internal/conn3x/modules"
	"github.com/opentofu/opentofu/internal/conn3x/modules/file"
	"github.com/opentofu/opentofu/internal/conn3x/transport/ssh"
)

// Copy is a directory as it should be on the host.
type Copy struct {
	Source string // a directory on the controller
	Dest   string // an absolute directory on the host
	Mode   string // every file's mode, four octal digits
	Owner  string // "" leaves each file's owner as it is
	Group  string
	Delete bool // remove files under Dest that Source doesn't have
}

// MaxFiles and MaxBytes bound what one step copies. A tree bigger than
// either belongs in a package or an image, not a step.
const (
	MaxFiles = 5000
	MaxBytes = 1 << 30
)

// Validate checks a Copy before anything reads the source or the host.
func (c Copy) Validate() error {
	if c.Source == "" {
		return fmt.Errorf("source must name a directory on the machine Conn3x runs on")
	}
	if !path.IsAbs(c.Dest) || path.Clean(c.Dest) == "/" || path.Clean(c.Dest) != c.Dest {
		return fmt.Errorf("destination %q must be an absolute, clean path, and not /", c.Dest)
	}
	return file.Desired{Path: c.Dest + "/x", Mode: c.Mode}.Validate()
}

// Local reads Source: every regular file's path relative to it, with
// slashes, and its content. A link, a device or anything else that isn't a
// file or directory is an error, so what's copied is what's in the tree.
func (c Copy) Local() (map[string][]byte, error) {
	files := map[string][]byte{}
	var total int64
	err := filepath.WalkDir(c.Source, func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			return nil
		}
		rel, err := filepath.Rel(c.Source, p)
		if err != nil {
			return err
		}
		if !d.Type().IsRegular() {
			return fmt.Errorf("%s in the source is a link or a special file; directory_copy copies regular files only", filepath.ToSlash(rel))
		}
		if len(files) >= MaxFiles {
			return fmt.Errorf("the source has more than %d files", MaxFiles)
		}
		b, err := os.ReadFile(p)
		if err != nil {
			return err
		}
		if total += int64(len(b)); total > MaxBytes {
			return fmt.Errorf("the source is over %d MiB", MaxBytes>>20)
		}
		files[filepath.ToSlash(rel)] = b
		return nil
	})
	if err != nil {
		return nil, fmt.Errorf("reading source %s: %w", c.Source, err)
	}
	return files, nil
}

// Sums are each file's SHA-256, hex, by relative path.
func Sums(files map[string][]byte) map[string]string {
	sums := map[string]string{}
	for rel, b := range files {
		s := sha256.Sum256(b)
		sums[rel] = hex.EncodeToString(s[:])
	}
	return sums
}

// Remote is a file under Dest as the host has it.
type Remote struct {
	Sum, Mode, Owner, Group string
}

// Read lists the regular files under Dest with their sums, modes and
// owners. A missing Dest is an empty map. It runs under the same path
// guard as a file step, and find doesn't follow links.
func Read(ctx context.Context, r modules.Runner, dest string) (map[string]Remote, error) {
	script := modules.Settled + fmt.Sprintf(`p=%s
route_settled "$p" || { echo missing; exit 0; }
[ -d "$p" ] || { echo missing; exit 0; }
cd -- "$p"
echo present
find . -type f -printf '%%m %%u %%g %%P\0'
printf '\0'
find . -type f -print0 | xargs -0 -r sha256sum -z --`, ssh.Quote(dest))
	res, err := r.Run(ctx, modules.Guard(script, modules.Follow(dest)), nil)
	if err != nil {
		return nil, err
	}
	if res.ExitCode != 0 {
		return nil, fmt.Errorf("reading %s: %s", dest, strings.TrimSpace(string(res.Stderr)))
	}
	head, body, _ := bytes.Cut(res.Stdout, []byte("\n"))
	out := map[string]Remote{}
	if string(head) != "present" {
		return out, nil
	}
	meta, sums, ok := bytes.Cut(body, []byte("\x00\x00"))
	if !ok {
		return nil, fmt.Errorf("reading %s: unexpected output", dest)
	}
	for _, rec := range bytes.Split(meta, []byte{0}) {
		f := strings.SplitN(string(rec), " ", 4)
		if len(f) == 4 {
			out[f[3]] = Remote{Mode: file.NormalizeMode(f[0]), Owner: f[1], Group: f[2]}
		}
	}
	for _, rec := range bytes.Split(sums, []byte{0}) {
		sum, p, ok := strings.Cut(string(rec), "  ")
		if !ok {
			continue
		}
		rel := strings.TrimPrefix(p, "./")
		if e, ok := out[rel]; ok {
			e.Sum = sum
			out[rel] = e
		}
	}
	return out, nil
}

// Plan is what Apply would do: the files to write and the ones to remove.
type Plan struct {
	Write, Remove []string
}

// Diff works out the Plan from the source's sums and the host's files.
func (c Copy) Diff(sums map[string]string, have map[string]Remote) Plan {
	var p Plan
	for rel, sum := range sums {
		h, ok := have[rel]
		if !ok || h.Sum != sum || h.Mode != file.NormalizeMode(c.Mode) || (c.Owner != "" && h.Owner != c.Owner) || (c.Group != "" && h.Group != c.Group) {
			p.Write = append(p.Write, rel)
		}
	}
	if c.Delete {
		for rel := range have {
			if _, ok := sums[rel]; !ok {
				p.Remove = append(p.Remove, rel)
			}
		}
	}
	slices.Sort(p.Write)
	slices.Sort(p.Remove)
	return p
}

// Empty reports whether the plan changes nothing.
func (p Plan) Empty() bool { return len(p.Write) == 0 && len(p.Remove) == 0 }

// Apply writes and removes what p says, each file the way file.Apply writes
// one: atomically, with its mode and owner, under the path guard.
//
// shortcut: one SSH command per file; a tree of thousands of changed files
// would want them batched into one stream.
func (c Copy) Apply(ctx context.Context, r modules.Runner, files map[string][]byte, p Plan) error {
	for _, rel := range p.Write {
		d := file.Desired{Path: c.Dest + "/" + rel, Content: string(files[rel]), Mode: file.NormalizeMode(c.Mode), Owner: c.Owner, Group: c.Group}
		if err := file.Apply(ctx, r, d); err != nil {
			return fmt.Errorf("writing %s: %w", d.Path, err)
		}
	}
	for _, rel := range p.Remove {
		if err := file.Delete(ctx, r, c.Dest+"/"+rel); err != nil {
			return fmt.Errorf("removing %s: %w", c.Dest+"/"+rel, err)
		}
	}
	return nil
}
