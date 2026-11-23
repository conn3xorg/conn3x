// Copyright (c) The Conn3x Authors
// SPDX-License-Identifier: MPL-2.0

package container

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"regexp"
	"slices"
	"strings"

	"github.com/opentofu/opentofu/internal/conn3x/modules"
	"github.com/opentofu/opentofu/internal/conn3x/transport/ssh"
)

// The things around a container: an image, a network and a volume, each
// read with the engine's inspect and made with its create or pull.

var (
	tagRe    = regexp.MustCompile(`^[A-Za-z0-9_][A-Za-z0-9_.-]{0,127}$`)
	driverRe = regexp.MustCompile(`^[a-zA-Z0-9][a-zA-Z0-9_./:-]*$`)
	// netDrivers are the drivers both engines make a network with; overlay
	// is Swarm's.
	netDrivers = []string{"bridge", "macvlan", "ipvlan"}
)

func validEngine(e string) error {
	if e != "" && e != "docker" && e != "podman" {
		return fmt.Errorf("engine %q must be \"docker\" or \"podman\", or unset", e)
	}
	return nil
}

func validName(n string) error {
	if !nameRe.MatchString(n) {
		return fmt.Errorf("name %q must start with a letter or digit, and hold only letters, digits and _ . -", n)
	}
	return nil
}

// inspect runs the engine's inspect for the object of kind named name,
// into out, and reports the engine it ran and whether the object exists.
func inspect(ctx context.Context, r modules.Runner, engine, kind, name string, out any) (string, bool, error) {
	script := pickEngine(engine) + `echo "$e"
"$e" ` + kind + ` inspect -- ` + ssh.Quote(name) + ` 2>/dev/null || echo missing
`
	res, err := r.Run(ctx, script, nil)
	if err != nil {
		return "", false, err
	}
	if res.ExitCode != 0 {
		return "", false, errors.New(strings.TrimSpace(string(res.Stderr) + string(res.Stdout)))
	}
	e, rest, _ := strings.Cut(string(res.Stdout), "\n")
	e = strings.TrimSpace(e)
	// inspect prints [] for a missing object before failing.
	if strings.HasSuffix(strings.TrimSpace(rest), "missing") {
		return e, false, nil
	}
	var got []json.RawMessage
	if err := json.Unmarshal([]byte(rest), &got); err != nil || len(got) != 1 {
		return "", false, fmt.Errorf("reading %s %s inspect for %s: %v", e, kind, name, err)
	}
	if err := json.Unmarshal(got[0], out); err != nil {
		return "", false, fmt.Errorf("reading %s %s inspect for %s: %v", e, kind, name, err)
	}
	return e, true, nil
}

// change runs script on the host, saying what failed in terms of what.
func change(ctx context.Context, r modules.Runner, what, script string) error {
	res, err := r.Run(ctx, script, nil)
	if err != nil {
		return err
	}
	if res.ExitCode != 0 {
		return fmt.Errorf("%s: %s", what, strings.TrimSpace(string(res.Stderr)+string(res.Stdout)))
	}
	return nil
}

// Image is an image kept on the host.
type Image struct {
	Engine string
	Name   string // a repository, or a full reference with its tag or digest
	Tag    string // "" when Name has one, or for latest
}

// HasTag reports whether a reference carries a tag or a digest.
func HasTag(ref string) bool {
	return strings.Contains(ref, "@") || strings.Contains(ref[strings.LastIndex(ref, "/")+1:], ":")
}

// Ref is the reference pulled and inspected.
func (i Image) Ref() string {
	if i.Tag != "" {
		return i.Name + ":" + i.Tag
	}
	return i.Name
}

func (i Image) Validate() error {
	if err := validEngine(i.Engine); err != nil {
		return err
	}
	if !imageRe.MatchString(i.Name) {
		return fmt.Errorf("name %q must be an image reference, such as docker.io/library/nginx", i.Name)
	}
	if i.Tag != "" {
		if HasTag(i.Name) {
			return fmt.Errorf("name %q has a tag or digest already, so tag can't be set too", i.Name)
		}
		if !tagRe.MatchString(i.Tag) {
			return fmt.Errorf("tag %q must be letters, digits and _ . -, not starting with . or -, at most 128 of them", i.Tag)
		}
	}
	return nil
}

// ImageActual is what the engine reports for an image.
type ImageActual struct {
	Engine string
	Exists bool
	ID     string
}

func ReadImage(ctx context.Context, r modules.Runner, i Image) (ImageActual, error) {
	if err := i.Validate(); err != nil {
		return ImageActual{}, err
	}
	var in struct{ Id string }
	e, ok, err := inspect(ctx, r, i.Engine, "image", i.Ref(), &in)
	return ImageActual{Engine: e, Exists: ok, ID: in.Id}, err
}

// ApplyImage pulls the image if it isn't on the host. One that's there is
// kept, even when its tag now names a newer one.
func ApplyImage(ctx context.Context, r modules.Runner, i Image) error {
	a, err := ReadImage(ctx, r, i)
	if err != nil || a.Exists {
		return err
	}
	if err := change(ctx, r, "image "+i.Ref(), ssh.Quote(a.Engine)+" pull -- "+ssh.Quote(i.Ref())+" >/dev/null"); err != nil {
		return err
	}
	if a, err = ReadImage(ctx, r, i); err == nil && !a.Exists {
		err = fmt.Errorf("image %s isn't on the host after the pull", i.Ref())
	}
	return err
}

// DeleteImage removes the image, if it's there. The engine refuses while a
// container uses it.
func DeleteImage(ctx context.Context, r modules.Runner, i Image) error {
	a, err := ReadImage(ctx, r, i)
	if err != nil || !a.Exists {
		return err
	}
	return change(ctx, r, "image "+i.Ref(), ssh.Quote(a.Engine)+" image rm -- "+ssh.Quote(i.Ref())+" >/dev/null")
}

// Network is a user-defined network.
type Network struct {
	Engine string
	Name   string
	Driver string // "bridge" when unset
	Subnet string // the engine picks one when unset
}

func (n Network) driver() string {
	if n.Driver == "" {
		return "bridge"
	}
	return n.Driver
}

func (n Network) Validate() error {
	if err := validEngine(n.Engine); err != nil {
		return err
	}
	if err := validName(n.Name); err != nil {
		return err
	}
	if !slices.Contains(netDrivers, n.driver()) {
		return fmt.Errorf("driver %q must be one of %s", n.Driver, strings.Join(netDrivers, ", "))
	}
	if n.Subnet != "" {
		_, ipnet, err := net.ParseCIDR(n.Subnet)
		if err != nil {
			return fmt.Errorf("subnet %q must be a CIDR block, such as 10.89.0.0/24", n.Subnet)
		}
		// Written as the engines print it, so the two compare as strings.
		if ipnet.String() != n.Subnet {
			return fmt.Errorf("subnet %q must be written %s", n.Subnet, ipnet)
		}
	}
	return nil
}

// NetworkActual is what the engine reports for a network.
type NetworkActual struct {
	Engine  string
	Exists  bool
	Driver  string
	Subnets []string
}

// networkInspected reads both engines: Docker writes Driver and
// IPAM.Config, Podman driver and subnets, and field names match either case.
type networkInspected struct {
	Name   string
	Driver string
	IPAM   struct{ Config []struct{ Subnet string } }
	Subn   []struct{ Subnet string } `json:"subnets"`
}

func ReadNetwork(ctx context.Context, r modules.Runner, n Network) (NetworkActual, error) {
	if err := n.Validate(); err != nil {
		return NetworkActual{}, err
	}
	var in networkInspected
	e, ok, err := inspect(ctx, r, n.Engine, "network", n.Name, &in)
	// Docker also finds a network by the start of its ID.
	a := NetworkActual{Engine: e, Exists: ok && in.Name == n.Name, Driver: in.Driver}
	for _, s := range append(in.IPAM.Config, in.Subn...) {
		a.Subnets = append(a.Subnets, s.Subnet)
	}
	return a, err
}

// Differences lists what about the network differs from n, in words.
func (n Network) Differences(a NetworkActual) []string {
	if !a.Exists {
		return []string{"it doesn't exist"}
	}
	var out []string
	if a.Driver != n.driver() {
		out = append(out, "its driver is "+a.Driver)
	}
	if n.Subnet != "" && !slices.Equal(a.Subnets, []string{n.Subnet}) {
		out = append(out, "its subnets are "+strings.Join(a.Subnets, ", "))
	}
	return out
}

// ApplyNetwork makes the network as n says, removing it first if it's
// there with other settings, which can't change in place. The engine
// refuses that while a container is on it.
func ApplyNetwork(ctx context.Context, r modules.Runner, n Network) error {
	a, err := ReadNetwork(ctx, r, n)
	if err != nil || len(n.Differences(a)) == 0 {
		return err
	}
	e, name := ssh.Quote(a.Engine), ssh.Quote(n.Name)
	script := ""
	if a.Exists {
		script = e + " network rm -- " + name + " >/dev/null || exit 1\n"
	}
	args := []string{"network", "create", "--driver", n.driver()}
	if n.Subnet != "" {
		args = append(args, "--subnet", n.Subnet)
	}
	script += e + " " + quoteAll(append(args, "--", n.Name)) + " >/dev/null"
	if err := change(ctx, r, "network "+n.Name, script); err != nil {
		return err
	}
	if a, err = ReadNetwork(ctx, r, n); err == nil && len(n.Differences(a)) > 0 {
		err = fmt.Errorf("network %s isn't as wanted after the change: %s", n.Name, strings.Join(n.Differences(a), ", "))
	}
	return err
}

// DeleteNetwork removes the network, if it's there.
func DeleteNetwork(ctx context.Context, r modules.Runner, n Network) error {
	a, err := ReadNetwork(ctx, r, n)
	if err != nil || !a.Exists {
		return err
	}
	return change(ctx, r, "network "+n.Name, ssh.Quote(a.Engine)+" network rm -- "+ssh.Quote(n.Name)+" >/dev/null")
}

// Volume is a named volume.
type Volume struct {
	Engine string
	Name   string
	Driver string // "local" when unset
}

func (v Volume) driver() string {
	if v.Driver == "" {
		return "local"
	}
	return v.Driver
}

func (v Volume) Validate() error {
	if err := validEngine(v.Engine); err != nil {
		return err
	}
	if err := validName(v.Name); err != nil {
		return err
	}
	if !driverRe.MatchString(v.driver()) {
		return fmt.Errorf("driver %q must be a volume driver's name, such as local", v.Driver)
	}
	return nil
}

// VolumeActual is what the engine reports for a volume.
type VolumeActual struct {
	Engine string
	Exists bool
	Driver string
}

func ReadVolume(ctx context.Context, r modules.Runner, v Volume) (VolumeActual, error) {
	if err := v.Validate(); err != nil {
		return VolumeActual{}, err
	}
	var in struct{ Driver string }
	e, ok, err := inspect(ctx, r, v.Engine, "volume", v.Name, &in)
	return VolumeActual{Engine: e, Exists: ok, Driver: in.Driver}, err
}

// InSync reports whether the volume is there with v's driver.
func (v Volume) InSync(a VolumeActual) bool { return a.Exists && a.Driver == v.driver() }

// ApplyVolume makes the volume if it isn't there. One there with another
// driver is left alone: changing it would take its data.
func ApplyVolume(ctx context.Context, r modules.Runner, v Volume) error {
	a, err := ReadVolume(ctx, r, v)
	if err != nil || v.InSync(a) {
		return err
	}
	if a.Exists {
		return fmt.Errorf("volume %s has driver %s, and changing it means removing the volume and its data, which Conn3x leaves to you: remove it with %s volume rm %s and apply again", v.Name, a.Driver, a.Engine, v.Name)
	}
	if err := change(ctx, r, "volume "+v.Name, ssh.Quote(a.Engine)+" "+quoteAll([]string{"volume", "create", "--driver", v.driver(), "--", v.Name})+" >/dev/null"); err != nil {
		return err
	}
	if a, err = ReadVolume(ctx, r, v); err == nil && !v.InSync(a) {
		err = fmt.Errorf("volume %s isn't there with driver %s after it was made", v.Name, v.driver())
	}
	return err
}

// DeleteVolume removes the volume and its data, if it's there. The engine
// refuses while a container uses it.
func DeleteVolume(ctx context.Context, r modules.Runner, v Volume) error {
	a, err := ReadVolume(ctx, r, v)
	if err != nil || !a.Exists {
		return err
	}
	return change(ctx, r, "volume "+v.Name, ssh.Quote(a.Engine)+" volume rm -- "+ssh.Quote(v.Name)+" >/dev/null")
}
