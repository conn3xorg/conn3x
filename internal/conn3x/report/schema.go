// Copyright (c) The Conn3x Authors
// SPDX-License-Identifier: MPL-2.0

package report

import (
	_ "embed"
	"encoding/json"
	"fmt"
	"sort"
	"strings"
)

// Schema is the report format, as JSON Schema.
//
//go:embed report.schema.json
var Schema []byte

// Validate checks a report against Schema. It understands only the JSON
// Schema keywords the schema uses, and fails on any other, so the schema
// can't grow a rule this check quietly skips.
func Validate(doc []byte) error {
	var schema, v any
	if err := json.Unmarshal(Schema, &schema); err != nil {
		return fmt.Errorf("schema: %w", err)
	}
	if err := json.Unmarshal(doc, &v); err != nil {
		return err
	}
	return check(schema.(map[string]any), v, "$")
}

// annotations are keywords that describe rather than constrain.
var annotations = map[string]bool{"$schema": true, "$id": true, "title": true, "description": true, "format": true}

func check(s map[string]any, v any, at string) error {
	for k := range s {
		switch k {
		case "type", "required", "properties", "additionalProperties", "enum", "items":
		default:
			if !annotations[k] {
				return fmt.Errorf("schema at %s uses %q, which Validate doesn't check", at, k)
			}
		}
	}
	if t, ok := s["type"].(string); ok && !isType(v, t) {
		return fmt.Errorf("%s: want %s, got %T", at, t, v)
	}
	if enum, ok := s["enum"].([]any); ok {
		found := false
		for _, e := range enum {
			found = found || e == v
		}
		if !found {
			return fmt.Errorf("%s: %v isn't one of %v", at, v, enum)
		}
	}
	if obj, ok := v.(map[string]any); ok {
		props, _ := s["properties"].(map[string]any)
		if req, ok := s["required"].([]any); ok {
			for _, r := range req {
				if _, ok := obj[r.(string)]; !ok {
					return fmt.Errorf("%s: missing %q", at, r)
				}
			}
		}
		keys := make([]string, 0, len(obj))
		for k := range obj {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		for _, k := range keys {
			path := at + "." + k
			if p, ok := props[k].(map[string]any); ok {
				if err := check(p, obj[k], path); err != nil {
					return err
				}
				continue
			}
			switch extra := s["additionalProperties"].(type) {
			case bool:
				if !extra {
					return fmt.Errorf("%s: not in the schema", path)
				}
			case map[string]any:
				if err := check(extra, obj[k], path); err != nil {
					return err
				}
			}
		}
	}
	if arr, ok := v.([]any); ok {
		if items, ok := s["items"].(map[string]any); ok {
			for i, e := range arr {
				if err := check(items, e, fmt.Sprintf("%s[%d]", at, i)); err != nil {
					return err
				}
			}
		}
	}
	return nil
}

func isType(v any, t string) bool {
	switch t {
	case "object":
		_, ok := v.(map[string]any)
		return ok
	case "array":
		_, ok := v.([]any)
		return ok
	case "string":
		_, ok := v.(string)
		return ok
	case "boolean":
		_, ok := v.(bool)
		return ok
	case "number":
		_, ok := v.(float64)
		return ok
	}
	return strings.TrimSpace(t) == "" // an unknown type never matches
}
