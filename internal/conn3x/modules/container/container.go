// Copyright (c) The Conn3x Authors
// SPDX-License-Identifier: MPL-2.0

// Package container keeps a container running with Docker or Podman,
// through the engine's own CLI: inspect to read it, rm and run to change
// it, since a container's settings can't change while it exists.
package container

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"maps"
	"math"
	"regexp"
	"slices"
	"sort"
	"strconv"
	"strings"

	"github.com/opentofu/opentofu/internal/conn3x/modules"
	"github.com/opentofu/opentofu/internal/conn3x/transport/ssh"
)

// Container is one container, by name.
type Container struct {
	Engine   string // "docker", "podman", or "" for whichever is installed
	Name     string
	Image    string
	Ports    []string // [ip:]host:container[/proto]
	Volumes  []string // source:destination[:options]
	Env      map[string]string
	Restart  string // "no" when unset
	Command  []string
	Networks []string // the engine's default network when empty

	// These are compared only when set, as Env is.
	User       string            // user[:group], by name or id
	Labels     map[string]string // compared by key: the image adds its own
	Memory     string            // such as 512m, as docker run --memory takes it
	CPUs       float64           // 0 for no limit
	LogDriver  string
	LogOptions map[string]string // compared by key; needs LogDriver
}

var (
	nameRe    = regexp.MustCompile(`^[a-zA-Z0-9][a-zA-Z0-9_.-]{0,127}$`)
	imageRe   = regexp.MustCompile(`^[a-zA-Z0-9][a-zA-Z0-9._/:@-]*$`)
	portRe    = regexp.MustCompile(`^(?:(\d{1,3}(?:\.\d{1,3}){3}|\[[0-9a-fA-F:]+\]):)?(\d{1,5}):(\d{1,5})(?:/(tcp|udp|sctp))?$`)
	volumeRe  = regexp.MustCompile(`^(/[^:\s]*|[a-zA-Z0-9][a-zA-Z0-9_.-]*):(/[^:\s]*)(?::([a-zA-Z,]+))?$`)
	envKeyRe  = regexp.MustCompile(`^[A-Za-z_][A-Za-z0-9_]*$`)
	restarts  = []string{"no", "always", "unless-stopped", "on-failure"}
	volumeOpt = []string{"ro", "rw", "z", "Z"}
	userRe    = regexp.MustCompile(`^[A-Za-z0-9_][A-Za-z0-9_.-]*(?::[A-Za-z0-9_][A-Za-z0-9_.-]*)?$`)
	labelRe   = regexp.MustCompile(`^[^=\s\x00-\x1f\x7f]+$`)
	logOptRe  = regexp.MustCompile(`^[a-zA-Z0-9][a-zA-Z0-9_.-]*$`)
	// sizeRe is the size format Docker and Podman both parse (go-units).
	sizeRe = regexp.MustCompile(`^(\d+(?:\.\d+)?) ?([kKmMgGtTpP])?[iI]?[bB]?$`)
)

// sizeBytes reads a size the way docker run --memory does, in powers of
// 1024, or with decimal in powers of 1000 as Podman reads --log-opt
// max-size. ok is false when s isn't a size.
func sizeBytes(s string, base float64) (n int64, ok bool) {
	m := sizeRe.FindStringSubmatch(s)
	if m == nil {
		return 0, false
	}
	f, err := strconv.ParseFloat(m[1], 64)
	if err != nil {
		return 0, false
	}
	if m[2] != "" {
		f *= math.Pow(base, float64(strings.Index("kmgtp", strings.ToLower(m[2]))+1))
	}
	return int64(f), true
}

// humanSize is how Podman's inspect shows a log max-size: go-units'
// HumanSize, four significant digits in powers of 1000.
func humanSize(n int64) string {
	f, units := float64(n), []string{"B", "kB", "MB", "GB", "TB", "PB"}
	i := 0
	for f >= 1000 && i < len(units)-1 {
		f /= 1000
		i++
	}
	return strconv.FormatFloat(f, 'g', 4, 64) + units[i]
}

// cpuArg is CPUs as --cpus takes it.
func (c Container) cpuArg() string { return strconv.FormatFloat(c.CPUs, 'f', -1, 64) }

func checkMap(what string, m map[string]string, key *regexp.Regexp, keyRule string) error {
	for k, v := range m {
		if !key.MatchString(k) {
			return fmt.Errorf("%s key %q must %s", what, k, keyRule)
		}
		if strings.ContainsAny(v, "\n\r\x00") {
			return fmt.Errorf("%s %s can't hold a line break", what, k)
		}
	}
	return nil
}

func (c Container) restart() string {
	if c.Restart == "" {
		return "no"
	}
	return c.Restart
}

// Validate checks a Container before anything reaches the host.
func (c Container) Validate() error {
	if c.Engine != "" && c.Engine != "docker" && c.Engine != "podman" {
		return fmt.Errorf("engine %q must be \"docker\" or \"podman\", or unset", c.Engine)
	}
	if !nameRe.MatchString(c.Name) {
		return fmt.Errorf("name %q must start with a letter or digit, and hold only letters, digits and _ . -", c.Name)
	}
	if !imageRe.MatchString(c.Image) {
		return fmt.Errorf("image %q must be an image reference, such as docker.io/library/nginx:1.30", c.Image)
	}
	for _, p := range c.Ports {
		if !portRe.MatchString(p) {
			return fmt.Errorf("ports %q must be host:container, such as 8080:80, optionally with an address in front and /tcp, /udp or /sctp after", p)
		}
	}
	for _, v := range c.Volumes {
		m := volumeRe.FindStringSubmatch(v)
		if m == nil {
			return fmt.Errorf("volumes %q must be source:destination, with an absolute host path or a volume name as the source, and an absolute destination", v)
		}
		for _, o := range strings.Split(m[3], ",") {
			if o != "" && !slices.Contains(volumeOpt, o) {
				return fmt.Errorf("volumes %q: option %q isn't one of ro, rw, z, Z", v, o)
			}
		}
	}
	for k, v := range c.Env {
		if !envKeyRe.MatchString(k) {
			return fmt.Errorf("env key %q must be a variable name: letters, digits and _, not starting with a digit", k)
		}
		if strings.ContainsAny(v, "\n\r\x00") {
			return fmt.Errorf("env %s can't hold a line break", k)
		}
	}
	if !slices.Contains(restarts, c.restart()) {
		return fmt.Errorf("restart %q must be one of %s", c.Restart, strings.Join(restarts, ", "))
	}
	if c.User != "" && !userRe.MatchString(c.User) {
		return fmt.Errorf("user %q must be a user name or id, optionally with :group after, such as 1000:1000", c.User)
	}
	if err := checkMap("labels", c.Labels, labelRe, "be one or more characters without =, spaces or control characters, such as traefik.enable"); err != nil {
		return err
	}
	if n, ok := sizeBytes(c.Memory, 1024); c.Memory != "" && (!ok || n <= 0) {
		return fmt.Errorf("memory %q must be a size, such as 512m or 2g: a number with b, k, m, g, t or p after", c.Memory)
	}
	if c.CPUs < 0 || math.IsNaN(c.CPUs) || math.IsInf(c.CPUs, 0) {
		return fmt.Errorf("cpus %s can't be below 0: it's how many CPUs the container can use, such as 1.5", c.cpuArg())
	}
	if c.LogDriver != "" && !driverRe.MatchString(c.LogDriver) {
		return fmt.Errorf("log_driver %q must name a logging driver, such as json-file, journald or local", c.LogDriver)
	}
	if len(c.LogOptions) > 0 && c.LogDriver == "" {
		return errors.New("log_options needs log_driver: the options belong to one driver")
	}
	if err := checkMap("log_options", c.LogOptions, logOptRe, "be an option name, such as max-size"); err != nil {
		return err
	}
	for i, n := range c.Networks {
		if !nameRe.MatchString(n) || n == "host" || n == "none" {
			return fmt.Errorf("networks %q must name a network, starting with a letter or digit and holding only letters, digits and _ . -; host and none are network modes, which this step doesn't set", n)
		}
		if slices.Contains(c.Networks[:i], n) {
			return fmt.Errorf("networks lists %s twice", n)
		}
	}
	return nil
}

// engine is the shell that picks the engine into $e.
func (c Container) engine() string { return pickEngine(c.Engine) }

// pickEngine is the shell that puts engine into $e, or whichever is
// installed when engine is "".
func pickEngine(engine string) string {
	if engine != "" {
		return "e=" + engine + "\ncommand -v " + engine + ` >/dev/null 2>&1 || { echo "` + engine + ` isn't installed on this host" >&2; exit 1; }` + "\n"
	}
	return `if command -v docker >/dev/null 2>&1; then e=docker
elif command -v podman >/dev/null 2>&1; then e=podman
else echo "neither docker nor podman is installed on this host; add a package step for one of them before this one" >&2; exit 1; fi
`
}

// Actual is what the engine reports for the container's name.
type Actual struct {
	Engine   string
	Exists   bool
	Running  bool
	Image    string
	Env      map[string]string
	Ports    []string // normalised, sorted
	Mounts   []string // normalised, sorted
	Restart  string
	Command  []string
	Networks []string // sorted

	User       string
	Labels     map[string]string // the image's as well as the container's
	Memory     int64             // bytes, 0 for no limit
	NanoCPUs   int64             // 0 for no limit
	LogDriver  string
	LogOptions map[string]string // what the engine shows of them
}

// inspected is the part of inspect's output Conn3x reads; Docker and
// Podman agree on these fields.
type inspected struct {
	Config struct {
		Image  string
		Env    []string
		Cmd    []string
		User   string
		Labels map[string]string
	}
	State      struct{ Running bool }
	HostConfig struct {
		PortBindings  map[string][]struct{ HostIp, HostPort string }
		RestartPolicy struct{ Name string }
		Memory        int64
		NanoCpus      int64
		// Docker shows options in Config; Podman leaves it null and shows
		// path, tag and max-size as fields of their own.
		LogConfig struct {
			Type            string
			Config          map[string]string
			Path, Tag, Size string
		}
	}
	Mounts []struct {
		Type, Name, Source, Destination string
		RW                              bool
	}
	NetworkSettings struct{ Networks map[string]json.RawMessage }
}

// Read inspects the container named c.Name.
func Read(ctx context.Context, r modules.Runner, c Container) (Actual, error) {
	if err := c.Validate(); err != nil {
		return Actual{}, err
	}
	script := c.engine() + `echo "$e"
"$e" container inspect -- ` + ssh.Quote(c.Name) + ` 2>/dev/null || echo missing
`
	res, err := r.Run(ctx, script, nil)
	if err != nil {
		return Actual{}, err
	}
	if res.ExitCode != 0 {
		return Actual{}, errors.New(strings.TrimSpace(string(res.Stderr) + string(res.Stdout)))
	}
	engine, rest, _ := strings.Cut(string(res.Stdout), "\n")
	a := Actual{Engine: strings.TrimSpace(engine)}
	// inspect prints [] for a missing container before failing; the script
	// then says so.
	if strings.HasSuffix(strings.TrimSpace(rest), "missing") {
		return a, nil
	}
	var got []inspected
	if err := json.Unmarshal([]byte(rest), &got); err != nil || len(got) != 1 {
		return Actual{}, fmt.Errorf("reading %s container inspect for %s: %v", a.Engine, c.Name, err)
	}
	in := got[0]
	a.Exists, a.Running, a.Image, a.Command = true, in.State.Running, in.Config.Image, in.Config.Cmd
	a.Env = map[string]string{}
	for _, kv := range in.Config.Env {
		k, v, _ := strings.Cut(kv, "=")
		a.Env[k] = v
	}
	for proto, binds := range in.HostConfig.PortBindings {
		cport, p, _ := strings.Cut(proto, "/")
		for _, b := range binds {
			a.Ports = append(a.Ports, portKey(b.HostIp, b.HostPort, cport, p))
		}
	}
	sort.Strings(a.Ports)
	for _, m := range in.Mounts {
		src := m.Source
		if m.Type == "volume" {
			src = m.Name
		}
		a.Mounts = append(a.Mounts, mountKey(src, m.Destination, !m.RW))
	}
	sort.Strings(a.Mounts)
	for n := range in.NetworkSettings.Networks {
		a.Networks = append(a.Networks, n)
	}
	sort.Strings(a.Networks)
	a.User, a.Labels, a.Memory, a.NanoCPUs = in.Config.User, in.Config.Labels, in.HostConfig.Memory, in.HostConfig.NanoCpus
	lc := in.HostConfig.LogConfig
	a.LogDriver, a.LogOptions = lc.Type, lc.Config
	if a.LogOptions == nil {
		a.LogOptions = map[string]string{}
		for k, v := range map[string]string{"path": lc.Path, "tag": lc.Tag, "max-size": lc.Size} {
			// Podman shows -1B for no max-size.
			if v != "" && v != "-1B" {
				a.LogOptions[k] = v
			}
		}
	}
	a.Restart = in.HostConfig.RestartPolicy.Name
	if a.Restart == "" {
		a.Restart = "no"
	}
	return a, nil
}

// portKey normalises a binding: no address and 0.0.0.0 mean the same, and
// tcp is the default protocol.
func portKey(ip, host, container, proto string) string {
	ip = strings.Trim(ip, "[]")
	if ip == "0.0.0.0" || ip == "::" {
		ip = ""
	}
	if proto == "" {
		proto = "tcp"
	}
	return ip + "|" + host + "|" + container + "/" + proto
}

func mountKey(src, dst string, ro bool) string {
	return fmt.Sprintf("%s|%s|ro=%v", strings.TrimSuffix(src, "/"), strings.TrimSuffix(dst, "/"), ro)
}

// wantedPorts and wantedMounts are c's, normalised as Read normalises.
func (c Container) wantedPorts() []string {
	var out []string
	for _, p := range c.Ports {
		m := portRe.FindStringSubmatch(p)
		out = append(out, portKey(m[1], m[2], m[3], m[4]))
	}
	sort.Strings(out)
	return out
}

func (c Container) wantedMounts() []string {
	var out []string
	for _, v := range c.Volumes {
		m := volumeRe.FindStringSubmatch(v)
		out = append(out, mountKey(m[1], m[2], slices.Contains(strings.Split(m[3], ","), "ro")))
	}
	sort.Strings(out)
	return out
}

// normalImage is an image reference as both engines store it: Podman
// writes docker.io/library/nginx:latest where Docker keeps nginx.
// shortcut: a short name Podman resolves through its own search registries
// to somewhere else than docker.io shows as a difference; the docs say to
// write images in full.
func normalImage(ref string) string {
	name, digest, hasDigest := strings.Cut(ref, "@")
	first, _, hasSlash := strings.Cut(name, "/")
	if !hasSlash || (!strings.ContainsAny(first, ".:") && first != "localhost") {
		if !hasSlash {
			name = "library/" + name
		}
		name = "docker.io/" + name
	}
	if last := name[strings.LastIndex(name, "/")+1:]; !strings.Contains(last, ":") && !hasDigest {
		name += ":latest"
	}
	if hasDigest {
		return name + "@" + digest
	}
	return name
}

// Differences lists what about the container differs from c, in words.
func (c Container) Differences(a Actual) []string {
	if !a.Exists {
		return []string{"it doesn't exist"}
	}
	var out []string
	if normalImage(a.Image) != normalImage(c.Image) {
		out = append(out, fmt.Sprintf("its image is %s", a.Image))
	}
	if !slices.Equal(a.Ports, c.wantedPorts()) {
		out = append(out, "its ports differ")
	}
	if !slices.Equal(a.Mounts, c.wantedMounts()) {
		out = append(out, "its volumes differ")
	}
	for k, v := range c.Env {
		if got, ok := a.Env[k]; !ok || got != v {
			out = append(out, "its env differs")
			break
		}
	}
	if a.Restart != c.restart() {
		out = append(out, fmt.Sprintf("its restart policy is %s", a.Restart))
	}
	if len(c.Command) > 0 && !slices.Equal(a.Command, c.Command) {
		out = append(out, "its command differs")
	}
	if want := slices.Sorted(slices.Values(c.Networks)); len(want) > 0 && !slices.Equal(a.Networks, want) {
		out = append(out, "its networks are "+strings.Join(a.Networks, ", "))
	}
	if c.User != "" && a.User != c.User {
		out = append(out, fmt.Sprintf("its user is %q", a.User))
	}
	if differ(c.Labels, a.Labels, nil) {
		out = append(out, "its labels differ")
	}
	if want, _ := sizeBytes(c.Memory, 1024); c.Memory != "" && a.Memory != want {
		out = append(out, fmt.Sprintf("its memory limit is %d bytes", a.Memory))
	}
	if c.CPUs > 0 && a.NanoCPUs != int64(math.Round(c.CPUs*1e9)) {
		out = append(out, fmt.Sprintf("its cpus limit is %s", strconv.FormatFloat(float64(a.NanoCPUs)/1e9, 'f', -1, 64)))
	}
	if c.LogDriver != "" && logDriver(a.Engine, a.LogDriver) != logDriver(a.Engine, c.LogDriver) {
		out = append(out, "its log driver is "+a.LogDriver)
	}
	if a.Engine == "podman" {
		// Podman shows only path, tag and max-size, the last rounded.
		if differ(c.LogOptions, a.LogOptions, func(k, v string) (string, bool) {
			if k == "max-size" {
				n, ok := sizeBytes(v, 1000)
				return humanSize(n), ok
			}
			return v, k == "path" || k == "tag"
		}) {
			out = append(out, "its log options differ")
		}
	} else if differ(c.LogOptions, a.LogOptions, nil) {
		out = append(out, "its log options differ")
	}
	return out
}

// differ reports whether any key of want has another value in got. shown,
// when set, is the value the engine shows for one wanted, and false for a
// key it doesn't show.
func differ(want, got map[string]string, shown func(k, v string) (string, bool)) bool {
	for k, v := range want {
		if shown != nil {
			var ok bool
			if v, ok = shown(k, v); !ok {
				continue
			}
		}
		if g, ok := got[k]; !ok || g != v {
			return true
		}
	}
	return false
}

// logDriver is a driver name as the engine means it: Podman takes
// json-file as another name for k8s-file.
func logDriver(engine, d string) string {
	if engine == "podman" && d == "json-file" {
		return "k8s-file"
	}
	return d
}

// InSync reports whether the container exists as c says, and runs.
func (c Container) InSync(a Actual) bool { return a.Running && len(c.Differences(a)) == 0 }

// Apply makes the container as c says: started if it only stopped, and
// otherwise removed and run again, since its settings can't change in
// place. Volumes keep their data.
func Apply(ctx context.Context, r modules.Runner, c Container) error {
	a, err := Read(ctx, r, c)
	if err != nil {
		return err
	}
	if c.InSync(a) {
		return nil
	}
	e := ssh.Quote(a.Engine)
	name := ssh.Quote(c.Name)
	var script string
	var stdin []byte
	if len(c.Differences(a)) == 0 {
		script = e + " start -- " + name
	} else {
		args := []string{"run", "-d", "--name", c.Name, "--restart", c.restart()}
		for _, p := range c.Ports {
			args = append(args, "-p", p)
		}
		for _, v := range c.Volumes {
			args = append(args, "-v", v)
		}
		if len(c.Networks) > 0 {
			args = append(args, "--network", c.Networks[0])
		}
		if c.User != "" {
			args = append(args, "--user", c.User)
		}
		for _, k := range slices.Sorted(maps.Keys(c.Labels)) {
			args = append(args, "--label", k+"="+c.Labels[k])
		}
		if c.Memory != "" {
			args = append(args, "--memory", c.Memory)
		}
		if c.CPUs > 0 {
			args = append(args, "--cpus", c.cpuArg())
		}
		if c.LogDriver != "" {
			args = append(args, "--log-driver", c.LogDriver)
		}
		for _, k := range slices.Sorted(maps.Keys(c.LogOptions)) {
			args = append(args, "--log-opt", k+"="+c.LogOptions[k])
		}
		if len(c.Env) > 0 {
			// Values on the command line would show in the host's process list.
			args = append(args, "--env-file", "/dev/stdin")
			keys := make([]string, 0, len(c.Env))
			for k := range c.Env {
				keys = append(keys, k)
			}
			sort.Strings(keys)
			for _, k := range keys {
				stdin = append(stdin, k+"="+c.Env[k]+"\n"...)
			}
		}
		args = append(append(args, "--", c.Image), c.Command...)
		image := ssh.Quote(c.Image)
		script = e + " image inspect -- " + image + " >/dev/null 2>&1 || " + e + " pull -- " + image + " >/dev/null || exit 1\n"
		if a.Exists {
			script += e + " rm -f -- " + name + " >/dev/null || exit 1\n"
		}
		script += e + " " + quoteAll(args) + " >/dev/null || exit 1"
		// One network at run, which every Docker and Podman takes; the rest
		// are joined after.
		for _, n := range c.Networks[min(1, len(c.Networks)):] {
			script += "\n" + e + " network connect -- " + ssh.Quote(n) + " " + name + " >/dev/null || exit 1"
		}
		if a.Engine == "podman" && (c.restart() == "always" || c.restart() == "unless-stopped") {
			// Podman has no daemon to restart containers after a reboot; its
			// podman-restart service does that.
			script += `
if command -v systemctl >/dev/null 2>&1; then
  if [ "$(id -u)" = 0 ]; then systemctl enable podman-restart.service >/dev/null 2>&1
  else systemctl --user enable podman-restart.service >/dev/null 2>&1; fi || echo "couldn't enable podman-restart.service, so the container won't start again after a reboot" >&2
fi`
		}
	}
	res, err := r.Run(ctx, script, stdin)
	if err != nil {
		return err
	}
	if res.ExitCode != 0 {
		return fmt.Errorf("container %s: %s", c.Name, strings.TrimSpace(string(res.Stderr)+string(res.Stdout)))
	}
	after, err := Read(ctx, r, c)
	if err != nil {
		return err
	}
	if !c.InSync(after) {
		why := c.Differences(after)
		if len(why) == 0 {
			why = []string{"it isn't running; see " + a.Engine + " logs " + c.Name}
		}
		return fmt.Errorf("container %s isn't as wanted after the change: %s", c.Name, strings.Join(why, ", "))
	}
	return nil
}

// Delete removes the container, if it exists.
func Delete(ctx context.Context, r modules.Runner, c Container) error {
	res, err := r.Run(ctx, c.engine()+`"$e" rm -f -- `+ssh.Quote(c.Name)+` >/dev/null 2>&1 || true`, nil)
	if err != nil {
		return err
	}
	if res.ExitCode != 0 {
		return errors.New(strings.TrimSpace(string(res.Stderr)))
	}
	return nil
}

func quoteAll(words []string) string {
	q := make([]string, len(words))
	for i, w := range words {
		q[i] = ssh.Quote(w)
	}
	return strings.Join(q, " ")
}
