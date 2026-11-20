// Copyright (c) The Conn3x Authors
// SPDX-License-Identifier: MPL-2.0

package windows

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/opentofu/opentofu/internal/conn3x/modules/windows/ps"
)

// ValidateTimeZone checks a Windows time zone ID, such as "Mountain
// Standard Time", before anything runs. Whether the host knows it is
// for ReadTimeZone to say.
func ValidateTimeZone(name string) error {
	switch {
	case strings.TrimSpace(name) == "":
		return errors.New("time zone is empty")
	case len(name) > 128:
		return errors.New("time zone is longer than any Windows zone ID")
	case strings.ContainsFunc(name, func(r rune) bool { return r < ' ' || r == 0x7f }):
		return fmt.Errorf("time zone %q has a control character", name)
	}
	return nil
}

// ReadTimeZone reports whether the host's time zone is name. Windows
// compares zone IDs without case, so this does too. A name the host
// doesn't know is an error naming the three closest IDs it does.
func ReadTimeZone(ctx context.Context, r ps.Runner, name string) (bool, error) {
	res, err := ps.Read(ctx, r, script("read_timezone.ps1"), map[string]any{"name": name})
	if err != nil {
		return false, err
	}
	var a struct {
		Current string   `json:"current"`
		Known   bool     `json:"known"`
		IDs     []string `json:"ids"`
	}
	if err := json.Unmarshal(res.Value, &a); err != nil {
		return false, fmt.Errorf("reading the time zone: %w", err)
	}
	if !a.Known {
		return false, fmt.Errorf("Windows has no time zone %q; the closest it has are %s", name, quoteList(closest(name, a.IDs, 3)))
	}
	return strings.EqualFold(a.Current, name), nil
}

// ApplyTimeZone sets the host's time zone to name and checks it took.
func ApplyTimeZone(ctx context.Context, r ps.Runner, name string) error {
	res, err := ps.Apply(ctx, r, script("apply_timezone.ps1"), map[string]any{"name": name}, time.Minute)
	if err != nil {
		return err
	}
	var a struct {
		Current string `json:"current"`
	}
	if err := json.Unmarshal(res.Value, &a); err != nil {
		return fmt.Errorf("reading the time zone after setting it: %w", err)
	}
	if !strings.EqualFold(a.Current, name) {
		return fmt.Errorf("the time zone is %q after setting it to %q", a.Current, name)
	}
	return nil
}

// closest is the n IDs nearest to name by edit distance, ignoring case,
// nearest first, ties in the host's order. An ID that starts with what
// name nearly is, such as "Mountain Standard Time (Mexico)" for
// "Mountian Standard Time", scores that start plus one, so a qualifier
// on the end doesn't push it behind an unrelated zone.
func closest(name string, ids []string, n int) []string {
	want := []rune(strings.ToLower(name))
	type scored struct {
		id string
		d  int
	}
	all := make([]scored, len(ids))
	for i, id := range ids {
		have := []rune(strings.ToLower(id))
		d := editDistance(string(want), string(have))
		if len(have) > len(want) {
			d = min(d, editDistance(string(want), string(have[:len(want)]))+1)
		}
		all[i] = scored{id, d}
	}
	sort.SliceStable(all, func(i, j int) bool { return all[i].d < all[j].d })
	var out []string
	for i := 0; i < len(all) && i < n; i++ {
		out = append(out, all[i].id)
	}
	return out
}

// editDistance is the Levenshtein distance between a and b, by rune.
func editDistance(a, b string) int {
	x, y := []rune(a), []rune(b)
	prev := make([]int, len(y)+1)
	for j := range prev {
		prev[j] = j
	}
	for i := 1; i <= len(x); i++ {
		cur := make([]int, len(y)+1)
		cur[0] = i
		for j := 1; j <= len(y); j++ {
			cost := 1
			if x[i-1] == y[j-1] {
				cost = 0
			}
			cur[j] = min(prev[j]+1, cur[j-1]+1, prev[j-1]+cost)
		}
		prev = cur
	}
	return prev[len(y)]
}

func quoteList(ss []string) string {
	q := make([]string, len(ss))
	for i, s := range ss {
		q[i] = fmt.Sprintf("%q", s)
	}
	return strings.Join(q, ", ")
}
