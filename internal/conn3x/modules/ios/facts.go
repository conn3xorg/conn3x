// Copyright (c) The Conn3x Authors
// SPDX-License-Identifier: MPL-2.0

package ios

import (
	"context"
	"errors"
	"regexp"
	"strings"
)

// Facts are what show version says about a device.
type Facts struct {
	Hostname, Model, Version, Serial, Image string
	Type                                    string // "IOS-XE" or "IOS"
}

var (
	versionRe = regexp.MustCompile(`(?m)^Cisco IOS.*Version (\S+?),?\s`)
	uptimeRe  = regexp.MustCompile(`(?m)^(\S+) uptime is `)
	imageRe   = regexp.MustCompile(`System image file is "([^"]+)"`)
	serialRe  = regexp.MustCompile(`Processor board ID (\S+)`)
	modelRes  = []*regexp.Regexp{
		regexp.MustCompile(`(?m)^[Cc]isco (\S+)[^\n]*\(revision`),
		regexp.MustCompile(`(?m)^[Cc]isco (\S+)[^\n]*bytes of [^\n]*memory`),
	}
	iosXERe = regexp.MustCompile(`\sIOS-XE\s|Cisco IOS XE Software`)
)

// ParseVersion reads show version's output.
func ParseVersion(out string) (Facts, error) {
	var f Facts
	m := versionRe.FindStringSubmatch(out)
	if m == nil {
		return f, errors.New("show version didn't say a Cisco IOS version; is this an IOS device?")
	}
	f.Version = strings.TrimSuffix(m[1], ",")
	if m := uptimeRe.FindStringSubmatch(out); m != nil {
		f.Hostname = m[1]
	}
	if m := imageRe.FindStringSubmatch(out); m != nil {
		f.Image = m[1]
	}
	if m := serialRe.FindStringSubmatch(out); m != nil {
		f.Serial = m[1]
	}
	for _, re := range modelRes {
		if m := re.FindStringSubmatch(out); m != nil {
			f.Model = m[1]
			break
		}
	}
	f.Type = "IOS"
	if iosXERe.MatchString(out) {
		f.Type = "IOS-XE"
	}
	return f, nil
}

// ReadFacts runs show version on d and reads it.
func ReadFacts(ctx context.Context, d Device) (Facts, error) {
	out, err := Show(ctx, d, "show version")
	if err != nil {
		return Facts{}, err
	}
	return ParseVersion(out)
}
