// Copyright (c) The Conn3x Authors
// SPDX-License-Identifier: MPL-2.0

package firewall

import (
	"context"
	"errors"
	"fmt"
	"regexp"
	"slices"
	"strings"

	"github.com/opentofu/opentofu/internal/conn3x/modules"
	"github.com/opentofu/opentofu/internal/conn3x/modules/file"
	"github.com/opentofu/opentofu/internal/conn3x/transport/ssh"
)

// nftDir holds each table's file, as loaded, and what nft listed after it.
const nftDir = "/etc/conn3x/nftables"

// NFTable is one nftables table, owned whole: its chains, sets and rules,
// written as the body of a table block.
type NFTable struct {
	Family, Name string
	Content      string
}

var (
	nftFamilies = []string{"ip", "ip6", "inet", "arp", "bridge", "netdev"}
	nftName     = regexp.MustCompile(`^[A-Za-z][A-Za-z0-9_-]{0,63}$`)
	// A table's body can't reach past the table: no other table, no
	// flushing everything, no files pulled in from elsewhere.
	nftOutside = regexp.MustCompile(`(?m)^\s*(table|flush\s+ruleset|include|delete\s+table|define)\b`)
)

// Validate checks a table before anything reaches the host. nft itself
// checks the body, with nft -c, before it's loaded.
func (t NFTable) Validate() error {
	if !slices.Contains(nftFamilies, t.Family) {
		return fmt.Errorf("family %q must be one of %s", t.Family, strings.Join(nftFamilies, ", "))
	}
	if !nftName.MatchString(t.Name) {
		return fmt.Errorf("table %q must start with a letter and be letters, digits, _ and -", t.Name)
	}
	if strings.TrimSpace(t.Content) == "" {
		return errors.New("content must hold the table's chains and rules")
	}
	if m := nftOutside.FindString(t.Content); m != "" {
		return fmt.Errorf("content holds %q, which reaches outside this table; give it the table's chains, sets and rules only", strings.TrimSpace(m))
	}
	return nil
}

func (t NFTable) base() string { return nftDir + "/" + t.Family + "-" + t.Name }
func (t NFTable) unit() string { return "conn3x-nft-" + t.Family + "-" + t.Name + ".service" }
func (t NFTable) ref() string  { return t.Family + " " + t.Name }

// Script is what nft -f loads: the table made if it's missing, deleted,
// and defined again, in one transaction, so the old rules are never half
// replaced.
func (t NFTable) Script() string {
	return "table " + t.ref() + "\ndelete table " + t.ref() + "\ntable " + t.ref() + " {\n" + strings.TrimRight(t.Content, "\n") + "\n}\n"
}

const needNft = `command -v nft >/dev/null || { echo "nft isn't installed; add a package step for nftables first" >&2; exit 1; }`

// ReadNFTable reports whether the host has the table as the step wants it:
// the file holds this script, nft lists the table as it did after the
// script was loaded, and the unit that loads it at boot is enabled.
func ReadNFTable(ctx context.Context, r modules.Runner, t NFTable) (bool, error) {
	if err := t.Validate(); err != nil {
		return false, err
	}
	a, err := file.Read(ctx, r, t.base()+".nft")
	if err != nil || !a.Exists || a.Content != t.Script() {
		return false, err
	}
	res, err := r.Run(ctx, fmt.Sprintf(`%s
b=%s
live=$(nft list table %s 2>/dev/null) || { echo missing; exit 0; }
[ "$live" = "$(cat "$b.live" 2>/dev/null)" ] || { echo changed; exit 0; }
systemctl is-enabled --quiet %s && echo ok || echo disabled`, needNft, ssh.Quote(t.base()), t.ref(), ssh.Quote(t.unit())), nil)
	if err := check(res, err); err != nil {
		return false, err
	}
	return strings.TrimSpace(string(res.Stdout)) == "ok", nil
}

// SaveNFUndo records what takes the table back to how it is now, and
// returns the command that does it: the old table again, or none.
func SaveNFUndo(ctx context.Context, r modules.Runner, t NFTable) ([]string, error) {
	res, err := r.Run(ctx, fmt.Sprintf(`set -e
%s
mkdir -p -m 0700 %s
u=%s.undo
{ echo "table %s"; echo "delete table %s"; nft list table %s 2>/dev/null || true; } > "$u.tmp"
chmod 0600 "$u.tmp"
mv -f "$u.tmp" "$u"`, needNft, nftDir, ssh.Quote(t.base()), t.ref(), t.ref(), t.ref()), nil)
	if err := check(res, err); err != nil {
		return nil, err
	}
	return []string{"nft -f " + ssh.Quote(t.base()+".undo") + " && nft list table " + t.ref() + " > " + ssh.Quote(t.base()+".live") + " 2>/dev/null || true"}, nil
}

// ApplyNFTable checks the script with nft -c, writes it, loads it, records
// what nft lists after, and enables a unit that loads it at boot.
func ApplyNFTable(ctx context.Context, r modules.Runner, t NFTable) error {
	if err := t.Validate(); err != nil {
		return err
	}
	res, err := r.Run(ctx, fmt.Sprintf("%s\nmkdir -p -m 0700 %s", needNft, nftDir), nil)
	if err := check(res, err); err != nil {
		return err
	}
	// The dry run reads the script from stdin, so nothing is written yet.
	res, err = r.Run(ctx, "nft -c -f -", []byte(t.Script()))
	if err := check(res, err); err != nil {
		return fmt.Errorf("nft refused the table: %w", err)
	}
	if err := file.Apply(ctx, r, file.Desired{Path: t.base() + ".nft", Content: t.Script(), Mode: "0600", Owner: "root", Group: "root"}); err != nil {
		return err
	}
	unit := fmt.Sprintf("[Unit]\nDescription=nftables table %s, kept by Conn3x\nWants=network-pre.target\nBefore=network-pre.target\nAfter=nftables.service\n\n[Service]\nType=oneshot\nRemainAfterExit=yes\nExecStart=/bin/sh -c 'nft -f %s'\n\n[Install]\nWantedBy=multi-user.target\n", t.ref(), t.base()+".nft")
	if err := file.Apply(ctx, r, file.Desired{Path: "/etc/systemd/system/" + t.unit(), Content: unit, Mode: "0644", Owner: "root", Group: "root"}); err != nil {
		return err
	}
	res, err = r.Run(ctx, fmt.Sprintf(`set -e
b=%s
nft -f "$b.nft"
nft list table %s > "$b.live.tmp"
chmod 0600 "$b.live.tmp"
mv -f "$b.live.tmp" "$b.live"
systemctl daemon-reload
systemctl enable --quiet %s`, ssh.Quote(t.base()), t.ref(), ssh.Quote(t.unit())), nil)
	return check(res, err)
}

// DeleteNFTable takes the table out, and the unit and files that kept it.
// The undo file stays: under confirm_after, it's what puts the table back.
func DeleteNFTable(ctx context.Context, r modules.Runner, t NFTable) error {
	if err := t.Validate(); err != nil {
		return err
	}
	res, err := r.Run(ctx, fmt.Sprintf(`b=%s
if command -v nft >/dev/null && nft list table %s >/dev/null 2>&1; then nft delete table %s || exit 1; fi
systemctl disable --quiet %s 2>/dev/null
rm -f /etc/systemd/system/%s "$b.nft" "$b.live"
systemctl daemon-reload`, ssh.Quote(t.base()), t.ref(), t.ref(), ssh.Quote(t.unit()), ssh.Quote(t.unit())), nil)
	return check(res, err)
}
