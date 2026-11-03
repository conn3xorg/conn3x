// Copyright (c) The Conn3x Authors
// SPDX-License-Identifier: MPL-2.0

package windows

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/netip"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/opentofu/opentofu/internal/conn3x/modules/windows/ps"
)

var (
	// Pool and site names are looked up by name; anything a person wouldn't
	// type is kept out, as for firewall rules.
	iisName = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9 ._()-]{0,63}$`)
	// A host header is a DNS name, or a wildcard for one level.
	hostHeader = regexp.MustCompile(`^(\*\.)?[A-Za-z0-9]([A-Za-z0-9-]{0,62})(\.[A-Za-z0-9]([A-Za-z0-9-]{0,62}))*$`)
)

// IIS's own choices for these, as Windows reports them.
var (
	iisRuntimes   = []string{"", "v2.0", "v4.0"}
	iisPipelines  = map[string]string{"integrated": "Integrated", "classic": "Classic"}
	iisIdentities = []string{"ApplicationPoolIdentity", "NetworkService", "LocalService", "LocalSystem"}
)

func validIISName(kind, name string) error {
	if !iisName.MatchString(name) || strings.HasSuffix(name, " ") || strings.HasSuffix(name, ".") {
		return fmt.Errorf("%s name %q must start with a letter or digit, use only letters, digits, spaces and . _ ( ) -, and not end in a space or dot", kind, name)
	}
	return nil
}

// AppPool is an IIS application pool. Every field holds its value with
// defaults already filled in.
type AppPool struct {
	Name           string
	Started        bool
	RuntimeVersion string // "" is No Managed Code
	PipelineMode   string // integrated or classic
	Identity       string // one of iisIdentities
}

// Validate checks a pool before anything reaches a host.
func (p AppPool) Validate() error {
	if err := validIISName("app pool", p.Name); err != nil {
		return err
	}
	if !slices.Contains(iisRuntimes, p.RuntimeVersion) {
		return fmt.Errorf(`managed_runtime_version %q must be "v4.0", "v2.0" or "" for no managed code`, p.RuntimeVersion)
	}
	if _, ok := iisPipelines[p.PipelineMode]; !ok {
		return fmt.Errorf(`pipeline_mode %q must be "integrated" or "classic"`, p.PipelineMode)
	}
	if !slices.Contains(iisIdentities, p.Identity) {
		return fmt.Errorf("identity %q must be one of %s", p.Identity, strings.Join(iisIdentities, ", "))
	}
	return nil
}

// ActualAppPool is a pool as the host reports it.
type ActualAppPool struct {
	Installed      bool   `json:"installed"`
	Exists         bool   `json:"exists"`
	State          string `json:"state"`
	AutoStart      bool   `json:"auto_start"`
	RuntimeVersion string `json:"runtime"`
	PipelineMode   string `json:"pipeline"`
	Identity       string `json:"identity"`
}

// Matches reports whether the host has the pool as configured. A pool that
// is stopped but starts with IIS, or the other way round, doesn't match.
func (p AppPool) Matches(a ActualAppPool) bool {
	return a.Installed && a.Exists && a.State == iisState(p.Started) && a.AutoStart == p.Started &&
		strings.EqualFold(a.RuntimeVersion, p.RuntimeVersion) && strings.EqualFold(a.PipelineMode, p.PipelineMode) &&
		strings.EqualFold(a.Identity, p.Identity)
}

// iisState is the state Windows reports for a started or stopped pool or
// site. Starting, Stopping and Unknown match neither.
func iisState(started bool) string {
	if started {
		return "Started"
	}
	return "Stopped"
}

// ReadAppPool reads a pool by its name. With IIS missing, it's absent.
func ReadAppPool(ctx context.Context, r ps.Runner, name string) (ActualAppPool, error) {
	res, err := ps.Read(ctx, r, script("read_iis_app_pool.ps1"), map[string]any{"name": name})
	if err != nil {
		return ActualAppPool{}, err
	}
	var a ActualAppPool
	if err := json.Unmarshal(res.Value, &a); err != nil {
		return ActualAppPool{}, fmt.Errorf("reading app pool %s: the host's answer wasn't valid", name)
	}
	return a, nil
}

// ApplyAppPool creates a pool, or sets every setting of an existing one, and
// starts or stops it.
func ApplyAppPool(ctx context.Context, r ps.Runner, p AppPool) error {
	if err := p.Validate(); err != nil {
		return err
	}
	_, err := ps.Apply(ctx, r, script("apply_iis_app_pool.ps1"), map[string]any{
		"name": p.Name, "started": p.Started, "runtime": p.RuntimeVersion, "pipeline": iisPipelines[p.PipelineMode], "identity": p.Identity,
	}, 2*time.Minute)
	return err
}

// ApplyAppPoolRemove deletes a pool, if it's there.
func ApplyAppPoolRemove(ctx context.Context, r ps.Runner, name string) error {
	if err := validIISName("app pool", name); err != nil {
		return err
	}
	_, err := ps.Apply(ctx, r, script("apply_iis_app_pool_remove.ps1"), map[string]any{"name": name}, 2*time.Minute)
	return err
}

// Binding is a site binding. Only http for now.
type Binding struct {
	Protocol   string // http
	IP         string // * or an address
	Port       int
	HostHeader string
}

// Information is the binding as IIS writes it: ip:port:host, an IPv6
// address in brackets, the host in lower case.
func (b Binding) Information() (string, error) {
	if b.Protocol != "http" {
		return "", fmt.Errorf(`binding protocol %q must be "http"; https bindings aren't supported yet`, b.Protocol)
	}
	if b.Port < 1 || b.Port > 65535 {
		return "", fmt.Errorf("binding port %d must be from 1 to 65535", b.Port)
	}
	ip := b.IP
	if ip != "*" {
		a, err := netip.ParseAddr(ip)
		if err != nil || a.Zone() != "" {
			return "", fmt.Errorf(`binding ip %q must be "*" or an IP address`, b.IP)
		}
		ip = a.Unmap().String()
		if a.Is6() && !a.Is4In6() {
			ip = "[" + ip + "]"
		}
	}
	if b.HostHeader != "" && (!hostHeader.MatchString(b.HostHeader) || len(b.HostHeader) > 253) {
		return "", fmt.Errorf("binding host_header %q must be a DNS name, such as www.example.com or *.example.com", b.HostHeader)
	}
	return ip + ":" + strconv.Itoa(b.Port) + ":" + strings.ToLower(b.HostHeader), nil
}

// Site is an IIS site.
type Site struct {
	Name         string
	PhysicalPath string
	AppPool      string // left as it is when empty; IIS's default for a new site
	Bindings     []Binding
	Started      bool
}

// Validate checks a site before anything reaches a host.
func (s Site) Validate() error {
	if err := validIISName("site", s.Name); err != nil {
		return err
	}
	if _, err := CleanLocalPath("physical_path", s.PhysicalPath); err != nil {
		return err
	}
	if strings.Contains(s.PhysicalPath, "%") {
		return errors.New("physical_path must not contain %, which IIS expands")
	}
	if s.AppPool != "" {
		if err := validIISName("app pool", s.AppPool); err != nil {
			return err
		}
	}
	if len(s.Bindings) == 0 {
		return errors.New("a site needs at least one binding")
	}
	_, err := s.bindingSet()
	return err
}

// bindingSet is the bindings as protocol/information, sorted.
func (s Site) bindingSet() ([]string, error) {
	var out []string
	for _, b := range s.Bindings {
		info, err := b.Information()
		if err != nil {
			return nil, err
		}
		k := b.Protocol + "/" + info
		if slices.Contains(out, k) {
			return nil, fmt.Errorf("binding %s is given twice", info)
		}
		out = append(out, k)
	}
	slices.Sort(out)
	return out, nil
}

// ActualBinding is a binding as the host reports it.
type ActualBinding struct {
	Protocol    string `json:"protocol"`
	Information string `json:"information"`
}

// ActualSite is a site as the host reports it.
type ActualSite struct {
	Installed    bool            `json:"installed"`
	Exists       bool            `json:"exists"`
	State        string          `json:"state"`
	AutoStart    bool            `json:"auto_start"`
	PhysicalPath string          `json:"physical_path"`
	AppPool      string          `json:"app_pool"`
	Bindings     []ActualBinding `json:"bindings"`
}

func samePath(a, b string) bool {
	trim := func(p string) string { return strings.TrimRight(strings.ReplaceAll(p, "/", `\`), `\`) }
	return strings.EqualFold(trim(a), trim(b))
}

// Matches reports whether the host has the site as configured. Bindings are
// the whole list: one added by hand, https included, is drift.
func (s Site) Matches(a ActualSite) bool {
	if !a.Installed || !a.Exists || a.State != iisState(s.Started) || a.AutoStart != s.Started ||
		!samePath(a.PhysicalPath, s.PhysicalPath) || (s.AppPool != "" && !strings.EqualFold(a.AppPool, s.AppPool)) {
		return false
	}
	want, err := s.bindingSet()
	if err != nil {
		return false
	}
	var have []string
	for _, b := range a.Bindings {
		have = append(have, strings.ToLower(b.Protocol+"/"+b.Information))
	}
	slices.Sort(have)
	return slices.Equal(have, want)
}

// ReadSite reads a site by its name. With IIS missing, it's absent.
func ReadSite(ctx context.Context, r ps.Runner, name string) (ActualSite, error) {
	res, err := ps.Read(ctx, r, script("read_iis_site.ps1"), map[string]any{"name": name})
	if err != nil {
		return ActualSite{}, err
	}
	var a ActualSite
	if err := json.Unmarshal(res.Value, &a); err != nil {
		return ActualSite{}, fmt.Errorf("reading site %s: the host's answer wasn't valid", name)
	}
	return a, nil
}

// ApplySite creates a site, or sets every setting of an existing one, and
// starts or stops it.
func ApplySite(ctx context.Context, r ps.Runner, s Site) error {
	if err := s.Validate(); err != nil {
		return err
	}
	path, _ := CleanLocalPath("physical_path", s.PhysicalPath)
	bindings := []map[string]any{}
	for _, b := range s.Bindings {
		info, _ := b.Information()
		bindings = append(bindings, map[string]any{"protocol": b.Protocol, "information": info})
	}
	var pool any // null leaves it as it is
	if s.AppPool != "" {
		pool = s.AppPool
	}
	_, err := ps.Apply(ctx, r, script("apply_iis_site.ps1"), map[string]any{
		"name": s.Name, "physical_path": path, "app_pool": pool, "bindings": bindings, "started": s.Started,
	}, 2*time.Minute)
	return err
}

// ApplySiteRemove deletes a site, if it's there. Its files stay.
func ApplySiteRemove(ctx context.Context, r ps.Runner, name string) error {
	if err := validIISName("site", name); err != nil {
		return err
	}
	_, err := ps.Apply(ctx, r, script("apply_iis_site_remove.ps1"), map[string]any{"name": name}, 2*time.Minute)
	return err
}
