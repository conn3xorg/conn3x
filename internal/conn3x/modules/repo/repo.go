// Copyright (c) The Conn3x Authors
// SPDX-License-Identifier: MPL-2.0

// Package repo adds third-party package repositories: a dnf .repo file or a
// deb822 .sources file, each with its signing key beside it.
package repo

import (
	"context"
	"errors"
	"fmt"
	"path/filepath"
	"regexp"
	"strings"

	"github.com/opentofu/opentofu/internal/conn3x/modules"
	"github.com/opentofu/opentofu/internal/conn3x/modules/file"
	"github.com/opentofu/opentofu/internal/conn3x/modules/pkg"
	"github.com/opentofu/opentofu/internal/conn3x/transport/ssh"
)

var (
	repoName = regexp.MustCompile(`^[A-Za-z0-9_.-]+$`)
	aptWord  = regexp.MustCompile(`^[A-Za-z0-9_./-]+$`)
)

// Repo is a package repository and the key its packages are signed with.
type Repo struct {
	Name, URL, Key     string
	Suites, Components []string // apt only; components default to main
}

// Validate checks a Repo for the host's package manager family.
func (r Repo) Validate(family pkg.Family) error {
	if !repoName.MatchString(r.Name) {
		return fmt.Errorf("name %q may only use letters, digits, ., - and _", r.Name)
	}
	if !strings.HasPrefix(r.URL, "https://") && !strings.HasPrefix(r.URL, "http://") || strings.ContainsAny(r.URL, " \t\r\n") {
		return fmt.Errorf("url %q must be an http or https URL without spaces", r.URL)
	}
	if !strings.Contains(r.Key, "-----BEGIN PGP PUBLIC KEY BLOCK-----") {
		return errors.New("key must be an ASCII-armored public key (-----BEGIN PGP PUBLIC KEY BLOCK-----)")
	}
	if family != pkg.Deb {
		return nil
	}
	if len(r.Suites) == 0 {
		return errors.New("suites is required on Debian and Ubuntu, such as [\"noble\"]")
	}
	for _, w := range append(append([]string{}, r.Suites...), r.Components...) {
		if !aptWord.MatchString(w) {
			return fmt.Errorf("%q is not a valid suite or component", w)
		}
	}
	return nil
}

// Files returns the files the repository needs, by path.
func (r Repo) Files(family pkg.Family) map[string]string {
	if family == pkg.RPM {
		keyPath := "/etc/pki/rpm-gpg/RPM-GPG-KEY-conn3x-" + r.Name
		return map[string]string{
			keyPath: r.Key,
			"/etc/yum.repos.d/" + r.Name + ".repo": fmt.Sprintf("# Managed by Conn3x.\n[%s]\nname=%s\nbaseurl=%s\nenabled=1\ngpgcheck=1\ngpgkey=file://%s\n",
				r.Name, r.Name, r.URL, keyPath),
		}
	}
	keyPath := "/etc/apt/keyrings/conn3x-" + r.Name + ".asc"
	src := fmt.Sprintf("# Managed by Conn3x.\nTypes: deb\nURIs: %s\nSuites: %s\n", r.URL, strings.Join(r.Suites, " "))
	// A flat repository, whose suite is a path such as ./, has no components.
	if len(r.Suites) == 0 || !strings.HasSuffix(r.Suites[0], "/") {
		components := r.Components
		if len(components) == 0 {
			components = []string{"main"}
		}
		src += "Components: " + strings.Join(components, " ") + "\n"
	}
	return map[string]string{
		keyPath: r.Key,
		"/etc/apt/sources.list.d/" + r.Name + ".sources": src + "Signed-By: " + keyPath + "\n",
	}
}

// InSync reports whether every file the repository needs is in place.
func InSync(ctx context.Context, h modules.Runner, family pkg.Family, r Repo) (bool, error) {
	for path, want := range r.Files(family) {
		a, err := file.Read(ctx, h, path)
		if err != nil {
			return false, err
		}
		if !a.Exists || a.Content != want {
			return false, nil
		}
	}
	return true, nil
}

// Apply writes the files, then refreshes apt's package lists, so the next
// package step can install from the repository.
func Apply(ctx context.Context, h modules.Runner, family pkg.Family, r Repo) error {
	if err := r.Validate(family); err != nil {
		return err
	}
	for path, content := range r.Files(family) {
		if res, err := h.Run(ctx, "mkdir -p -m 0755 "+ssh.Quote(filepath.Dir(path)), nil); err != nil {
			return err
		} else if res.ExitCode != 0 {
			return fmt.Errorf("creating %s: %s", filepath.Dir(path), strings.TrimSpace(string(res.Stderr)))
		}
		if err := file.Apply(ctx, h, file.Desired{Path: path, Content: content, Mode: "0644", Owner: "root", Group: "root"}); err != nil {
			return err
		}
	}
	return refresh(ctx, h, family)
}

// Delete removes the files and refreshes apt's package lists.
func Delete(ctx context.Context, h modules.Runner, family pkg.Family, r Repo) error {
	for path := range r.Files(family) {
		if err := file.Delete(ctx, h, path); err != nil {
			return err
		}
	}
	return refresh(ctx, h, family)
}

func refresh(ctx context.Context, h modules.Runner, family pkg.Family) error {
	if family != pkg.Deb {
		return nil // dnf reads new repositories on its next run
	}
	if err := pkg.Run(ctx, h, "apt-get -q -o DPkg::Lock::Timeout=300 update"); err != nil {
		return fmt.Errorf("apt-get update: %w", err)
	}
	return nil
}
