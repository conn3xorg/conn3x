// Copyright (c) The Conn3x Authors
// SPDX-License-Identifier: MPL-2.0

package windows

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"regexp"
	"strings"
	"time"

	"github.com/opentofu/opentofu/internal/conn3x/modules/windows/ps"
)

// MaxContent is the most a file's content may hold. It travels on stdin, which
// stays reliable up to 3 MiB once base64 has grown it.
const MaxContent = 2 << 20

const fileApplyTimeout = 5 * time.Minute

var (
	localPath  = regexp.MustCompile(`^[A-Za-z]:\\`)
	deviceName = regexp.MustCompile(`(?i)^(con|prn|aux|nul|com[0-9]|lpt[0-9])(\..*)?$`)
	principal  = regexp.MustCompile(`^[^\x00-\x1f\x7f"/\[\]:;|=,+*?<>]{1,256}$`)
)

// CleanLocalPath checks a path a module writes to and returns it with
// backslashes and no trailing one. Only a plain path on a local drive will do:
// a share belongs to another machine's rules, and each form refused here is
// one Windows would quietly read as a different path than the one checked.
func CleanLocalPath(attr, p string) (string, error) {
	p = strings.ReplaceAll(p, "/", `\`)
	if err := ValidatePath(attr, p); err != nil {
		return "", err
	}
	if !localPath.MatchString(p) {
		return "", fmt.Errorf(`%s %q must be on a local drive, such as C:\app\config`, attr, p)
	}
	if len(p) > 259 {
		return "", fmt.Errorf("%s is longer than 259 characters", attr)
	}
	if len(p) > 3 {
		p = strings.TrimRight(p, `\`)
	}
	if len(p) == 3 {
		return p, nil
	}
	for _, c := range strings.Split(p[3:], `\`) {
		switch {
		case c == "":
			return "", fmt.Errorf("%s %q has an empty folder name", attr, p)
		case c == "." || c == "..":
			return "", fmt.Errorf("%s %q must not contain . or ..", attr, p)
		case strings.Contains(c, ":"):
			return "", fmt.Errorf("%s %q must not name an alternate data stream", attr, p)
		case strings.HasSuffix(c, ".") || strings.HasSuffix(c, " "):
			return "", fmt.Errorf("%s %q has a name ending in a dot or space, which Windows would drop", attr, p)
		case deviceName.MatchString(c):
			return "", fmt.Errorf("%s %q uses a device name, %s", attr, p, c)
		}
	}
	return p, nil
}

// Entry is one access rule as configured.
type Entry struct {
	Principal   string
	Rights      []string
	Type        string // "allow" (default) or "deny"
	Inheritance string // "none", "object", "container" or "container,object"; empty picks by kind
}

// rightsMasks are the named sets of file rights, without SYNCHRONIZE, which
// Windows adds or drops by itself.
var rightsMasks = map[string]uint32{
	"FullControl":       0x0f01ff,
	"Modify":            0x0301bf,
	"ReadAndExecute":    0x0200a9,
	"Read":              0x020089,
	"Write":             0x000116,
	"Delete":            0x010000,
	"ReadPermissions":   0x020000,
	"ChangePermissions": 0x040000,
	"TakeOwnership":     0x080000,
}

const synchronize = 0x100000

var inheritFlags = map[string]int{"": 0, "none": 0, "container": 1, "object": 2, "container,object": 3, "object,container": 3}

// ValidateEntry checks an entry before anything reaches a host.
func ValidateEntry(e Entry) error {
	if !principal.MatchString(e.Principal) {
		return fmt.Errorf("principal %q is not a user, group or SID", e.Principal)
	}
	if len(e.Rights) == 0 {
		return fmt.Errorf("the entry for %s lists no rights", e.Principal)
	}
	for _, r := range e.Rights {
		if _, ok := rightsMasks[r]; !ok {
			return fmt.Errorf("right %q is not one of FullControl, Modify, ReadAndExecute, Read, Write, Delete, ReadPermissions, ChangePermissions, TakeOwnership", r)
		}
	}
	if e.Type != "" && e.Type != "allow" && e.Type != "deny" {
		return fmt.Errorf(`type %q must be "allow" or "deny"`, e.Type)
	}
	if _, ok := inheritFlags[e.Inheritance]; !ok {
		return fmt.Errorf(`inheritance %q must be "none", "object", "container" or "container,object"`, e.Inheritance)
	}
	return nil
}

func (e Entry) mask() uint32 {
	var m uint32
	for _, r := range e.Rights {
		m |= rightsMasks[r]
	}
	return m
}

func (e Entry) flags(isDir bool) int {
	if e.Inheritance == "" && isDir {
		return 3
	}
	return inheritFlags[e.Inheritance]
}

// SecretEntries is who may read a write-only file unless its config says
// otherwise: SYSTEM and Administrators, like the 0600 default on Linux.
var SecretEntries = []Entry{
	{Principal: "S-1-5-18", Rights: []string{"FullControl"}},
	{Principal: "S-1-5-32-544", Rights: []string{"FullControl"}},
}

// ACE is one access rule as a host reports it.
type ACE struct {
	SID       string `json:"sid"`
	Mask      int64  `json:"mask"`
	Allow     bool   `json:"allow"`
	Flags     int    `json:"flags"`
	Only      int    `json:"only"`
	Inherited bool   `json:"inherited"`
}

// PathState is what a host reports about a path. It holds a hash, never content.
type PathState struct {
	Kind      string            `json:"kind"` // missing, file, directory or link
	LinkOnWay string            `json:"link_on_way"`
	SHA256    string            `json:"sha256"` // lower-case hex, once ReadPath returns it
	Protected bool              `json:"protected"`
	Owner     string            `json:"owner"`
	Entries   []ACE             `json:"entries"`
	SIDs      map[string]string `json:"sids"`
}

// ReadPath reports on a path and turns the given principals into SIDs. It reads
// no content and follows no link it finds at the path itself.
func ReadPath(ctx context.Context, r ps.Runner, path string, principals []string, hash bool) (PathState, error) {
	if principals == nil {
		principals = []string{}
	}
	res, err := ps.Read(ctx, r, script("read_path.ps1"), map[string]any{"path": path, "principals": principals, "hash": hash})
	if err != nil {
		return PathState{}, err
	}
	var s PathState
	if err := json.Unmarshal(res.Value, &s); err != nil {
		return PathState{}, fmt.Errorf("reading %s: %w", path, err)
	}
	s.SHA256 = strings.ToLower(s.SHA256)
	return s, nil
}

// Principals lists the names to resolve, including the owner if there is one.
func Principals(entries []Entry, owner string) []string {
	out := make([]string, 0, len(entries)+1)
	for _, e := range entries {
		out = append(out, e.Principal)
	}
	if owner != "" {
		out = append(out, owner)
	}
	return out
}

// normalMask folds the generic bits Windows sometimes stores into file rights,
// and drops SYNCHRONIZE. The JSON number is a signed 32-bit value.
func normalMask(m int64) uint32 {
	v := uint32(int32(m))
	if v&0x10000000 != 0 {
		v |= rightsMasks["FullControl"]
	}
	if v&0x80000000 != 0 {
		v |= rightsMasks["Read"]
	}
	if v&0x40000000 != 0 {
		v |= rightsMasks["Write"] | rightsMasks["ReadPermissions"]
	}
	if v&0x20000000 != 0 {
		v |= 0x0200a0
	}
	return v &^ (synchronize | 0xf0000000)
}

type aceKey struct {
	sid   string
	allow bool
	flags int
}

func (s PathState) wanted(entries []Entry) (map[aceKey]uint32, error) {
	want := map[aceKey]uint32{}
	for _, e := range entries {
		sid := s.SIDs[e.Principal]
		if sid == "" {
			return nil, fmt.Errorf("no such user or group on the host: %s", e.Principal)
		}
		want[aceKey{sid, e.Type != "deny", e.flags(s.Kind == "directory")}] |= e.mask()
	}
	return want, nil
}

// Matches reports whether a path's rules hold the entries. With exact, they
// must be the only rules there, none of them inherited; inherit asks for rules
// to be inherited or not, when set. Rules are compared by SID and mask, so
// names, case and display language can't cause a difference.
func (s PathState) Matches(entries []Entry, exact bool, inherit *bool, owner string) (bool, error) {
	want, err := s.wanted(entries)
	if err != nil {
		return false, err
	}
	if inherit != nil && s.Protected == *inherit {
		return false, nil
	}
	if owner != "" {
		sid := s.SIDs[owner]
		if sid == "" {
			return false, fmt.Errorf("no such user or group on the host: %s", owner)
		}
		if s.Owner != sid {
			return false, nil
		}
	}
	got := map[aceKey]uint32{}
	for _, a := range s.Entries {
		if exact && a.Inherited {
			if inherit == nil {
				continue // an authoritative list can't remove what is inherited
			}
			if !*inherit {
				return false, nil
			}
			continue
		}
		if a.Only != 0 {
			if exact {
				return false, nil // a rule no entry can describe
			}
			continue
		}
		got[aceKey{a.SID, a.Allow, a.Flags}] |= normalMask(a.Mask)
	}
	if exact && len(got) != len(want) {
		return false, nil
	}
	for k, m := range want {
		g, ok := got[k]
		if !ok || (exact && g != m) || g&m != m {
			return false, nil
		}
	}
	return true, nil
}

// Exact is true for a file or folder whose rules are the whole list.
func Exact(s PathState, entries []Entry) (bool, error) {
	f := false
	return s.Matches(entries, true, &f, "")
}

func wireEntries(entries []Entry, isDir bool) []map[string]any {
	out := make([]map[string]any, 0, len(entries))
	for _, e := range entries {
		out = append(out, map[string]any{"principal": e.Principal, "mask": e.mask(), "allow": e.Type != "deny", "flags": e.flags(isDir)})
	}
	return out
}

// ApplyFile writes a file through a temp file beside it, whose access is set at
// creation, then renames it into place, so nobody ever sees partial content or
// content under the wrong rules. With entries set they're the file's whole
// list, and a folder on the way that another account could change is refused;
// without, an existing file's rules are kept. It never follows a link.
func ApplyFile(ctx context.Context, r ps.Runner, path string, content []byte, entries []Entry, secrets []string) error {
	if len(content) > MaxContent {
		return errors.New("content is larger than 2 MiB")
	}
	_, err := ps.Apply(ctx, r, script("apply_file.ps1"), map[string]any{
		"path": path, "content": base64.StdEncoding.EncodeToString(content), "exact": len(entries) > 0, "entries": wireEntries(entries, false),
	}, fileApplyTimeout)
	if err != nil {
		return errors.New(Scrub(err.Error(), secrets))
	}
	return nil
}

// ApplyFileRemove deletes a file, or a link in its place, not what it points to.
func ApplyFileRemove(ctx context.Context, r ps.Runner, path string) error {
	_, err := ps.Apply(ctx, r, script("apply_file_remove.ps1"), map[string]any{"path": path}, fileApplyTimeout)
	return err
}

// ApplyDirectory makes a folder and any missing above it, giving the last one
// entries from the moment it exists, when there are any.
func ApplyDirectory(ctx context.Context, r ps.Runner, path string, entries []Entry) error {
	_, err := ps.Apply(ctx, r, script("apply_directory.ps1"), map[string]any{
		"path": path, "exact": len(entries) > 0, "entries": wireEntries(entries, true),
	}, fileApplyTimeout)
	return err
}

// ACL is what windows_acl manages on a path that already exists.
type ACL struct {
	Path          string
	Entries       []Entry
	Authoritative bool
	Inherit       *bool // nil leaves inheritance as it is
	Owner         string
}

// ApplyACL changes the rules on an existing path. It holds the path and the
// folders above it open while it works, so none can be swapped, and refuses
// links and files with other hard links. isDir is what a read just found.
func ApplyACL(ctx context.Context, r ps.Runner, a ACL, isDir bool) error {
	args := map[string]any{"path": a.Path, "entries": wireEntries(a.Entries, isDir), "exact": a.Authoritative, "owner": a.Owner}
	if a.Inherit != nil {
		args["inherit"] = *a.Inherit
	}
	_, err := ps.Apply(ctx, r, script("apply_acl.ps1"), args, 30*time.Minute)
	return err
}

// ValidateEntries checks a whole list.
func ValidateEntries(entries []Entry) error {
	for _, e := range entries {
		if err := ValidateEntry(e); err != nil {
			return err
		}
	}
	return nil
}
