// Copyright (c) The Conn3x Authors
// SPDX-License-Identifier: MPL-2.0

// Package hostdata reads layered host data, as Puppet's Hiera does: YAML
// files in a directory, named by a hierarchy such as hosts/{host}.yaml,
// then groups/{group}.yaml, then common.yaml, where a key's value comes
// from the first layer that sets it. So a value is set once for everyone
// and overridden per environment, group or host.
package hostdata

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strings"

	yaml "github.com/zclconf/go-cty-yaml"
	"github.com/zclconf/go-cty/cty"
	gyaml "gopkg.in/yaml.v3"
)

// HierarchyFile names the layers, highest priority first.
const HierarchyFile = "hierarchy.yaml"

// placeholder is {name} in a layer's path.
var placeholder = regexp.MustCompile(`\{([A-Za-z_][A-Za-z0-9_]*)\}`)

// safeValue is what a variable may be when it lands in a path.
var safeValue = regexp.MustCompile(`^[A-Za-z0-9_.@-]+$`)

// Result is the merged data, and for each key the file it came from.
type Result struct {
	Values map[string]cty.Value
	From   map[string]string
}

// Load reads dir's hierarchy, fills each layer's placeholders from vars, and
// merges the layers' top-level keys, first layer first. A variable with
// several values, such as a host's groups, makes one layer per value, in
// order. A layer whose file doesn't exist is skipped; a layer that names a
// variable vars doesn't have is an error, since a typo would otherwise
// quietly skip it.
func Load(dir string, vars map[string][]string) (Result, error) {
	b, err := os.ReadFile(filepath.Join(dir, HierarchyFile))
	if err != nil {
		return Result{}, fmt.Errorf("reading %s: %w; it lists the layers, such as hosts/{host}.yaml and common.yaml", HierarchyFile, err)
	}
	var h struct {
		Hierarchy []string `yaml:"hierarchy"`
	}
	if err := gyaml.Unmarshal(b, &h); err != nil || len(h.Hierarchy) == 0 {
		return Result{}, fmt.Errorf("%s must hold a hierarchy: list of layer paths, highest priority first; in a [ ] list, quote paths that hold {placeholders}, or YAML reads the braces as a mapping", HierarchyFile)
	}
	for k, vs := range vars {
		for _, v := range vs {
			if !safeValue.MatchString(v) {
				return Result{}, fmt.Errorf("variable %s is %q; values that name a layer's file are letters, digits and _ . @ - only", k, v)
			}
		}
	}
	res := Result{Values: map[string]cty.Value{}, From: map[string]string{}}
	for _, pattern := range h.Hierarchy {
		paths, err := expand(pattern, vars)
		if err != nil {
			return Result{}, err
		}
		for _, rel := range paths {
			if !filepath.IsLocal(rel) {
				return Result{}, fmt.Errorf("layer %q leaves the data directory", pattern)
			}
			values, err := readLayer(filepath.Join(dir, rel))
			if errors.Is(err, os.ErrNotExist) {
				continue
			}
			if err != nil {
				return Result{}, fmt.Errorf("%s: %w", rel, err)
			}
			for k, v := range values {
				if _, set := res.Values[k]; !set {
					res.Values[k], res.From[k] = v, filepath.ToSlash(rel)
				}
			}
		}
	}
	return res, nil
}

// expand fills a layer's placeholders: one path per combination of values.
func expand(pattern string, vars map[string][]string) ([]string, error) {
	paths := []string{pattern}
	for _, m := range placeholder.FindAllStringSubmatch(pattern, -1) {
		vs, ok := vars[m[1]]
		if !ok {
			return nil, fmt.Errorf("layer %q names {%s}, which vars doesn't set", pattern, m[1])
		}
		var next []string
		for _, p := range paths {
			for _, v := range vs {
				next = append(next, strings.ReplaceAll(p, m[0], v))
			}
		}
		paths = slices.Compact(next)
	}
	return paths, nil
}

// readLayer reads one YAML file of top-level keys.
func readLayer(path string) (map[string]cty.Value, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	if len(strings.TrimSpace(string(b))) == 0 {
		return nil, nil
	}
	ty, err := yaml.ImpliedType(b)
	if err != nil {
		return nil, err
	}
	v, err := yaml.Unmarshal(b, ty)
	if err != nil {
		return nil, err
	}
	if !v.Type().IsObjectType() && !v.Type().IsMapType() {
		return nil, errors.New("must be a mapping of keys to values at the top")
	}
	values := v.AsValueMap()
	if _, ok := values["sops"]; ok {
		return nil, errors.New("is encrypted with SOPS; read it with ephemeral \"conn3x_secrets\" instead, so its values stay out of state")
	}
	return values, nil
}
