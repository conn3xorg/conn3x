// Copyright (c) The Conn3x Authors
// SPDX-License-Identifier: MPL-2.0

package container

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"path"
	"regexp"
	"slices"
	"strings"

	"github.com/opentofu/opentofu/internal/conn3x/modules"
	"github.com/opentofu/opentofu/internal/conn3x/transport/ssh"
)

// Compose is a Compose project, kept up with docker compose on Docker or
// podman-compose on Podman.
type Compose struct {
	Engine        string
	ProjectDir    string
	ProjectName   string   // "" lets Compose take the directory's name
	Files         []string // relative to ProjectDir, or absolute; Compose's own default when empty
	EnvFiles      []string // .env in ProjectDir when empty
	Profiles      []string
	Services      []string // every service the files enable when empty
	State         string   // "present" (default), "stopped" or "absent"
	Pull          string   // "policy" (default), "always", "missing" or "never"
	RemoveOrphans bool
	Wait          bool
	Content       string // when set, written to the Compose file before each change
}

var (
	projectRe  = regexp.MustCompile(`^[a-z0-9][a-z0-9_-]*$`)
	profileRe  = regexp.MustCompile(`^[a-zA-Z0-9][a-zA-Z0-9_.-]*$`)
	states     = []string{"present", "stopped", "absent"}
	pulls      = []string{"policy", "always", "missing", "never"}
	composeDef = []string{"compose.yaml", "compose.yml", "docker-compose.yaml", "docker-compose.yml",
		"compose.override.yaml", "compose.override.yml", "docker-compose.override.yaml", "docker-compose.override.yml"}
)

func (c Compose) state() string {
	if c.State == "" {
		return "present"
	}
	return c.State
}

func (c Compose) pull() string {
	if c.Pull == "" {
		return "policy"
	}
	return c.Pull
}

// file is where Content goes.
func (c Compose) file() string {
	if len(c.Files) == 1 {
		return path.Join(c.ProjectDir, c.Files[0])
	}
	return path.Join(c.ProjectDir, "compose.yaml")
}

func (c Compose) Validate() error {
	if err := validEngine(c.Engine); err != nil {
		return err
	}
	if !path.IsAbs(c.ProjectDir) || path.Clean(c.ProjectDir) != c.ProjectDir || strings.ContainsAny(c.ProjectDir, "\n\r\x00") {
		return fmt.Errorf("project_dir %q must be an absolute path, written without a trailing slash or . and .. parts", c.ProjectDir)
	}
	if c.ProjectName != "" && !projectRe.MatchString(c.ProjectName) {
		return fmt.Errorf("project_name %q must start with a lowercase letter or digit, and hold only lowercase letters, digits, - and _", c.ProjectName)
	}
	for _, f := range append(slices.Clone(c.Files), c.EnvFiles...) {
		if f == "" || strings.HasPrefix(f, "-") || strings.ContainsAny(f, "\n\r\x00") {
			return fmt.Errorf("files and env_files %q must be a file name or path, not starting with -, on one line", f)
		}
	}
	for _, p := range c.Profiles {
		if !profileRe.MatchString(p) {
			return fmt.Errorf("profiles %q must start with a letter or digit, and hold only letters, digits and _ . -", p)
		}
	}
	for _, s := range c.Services {
		if !nameRe.MatchString(s) {
			return fmt.Errorf("services %q must start with a letter or digit, and hold only letters, digits and _ . -", s)
		}
	}
	if !slices.Contains(states, c.state()) {
		return fmt.Errorf("state %q must be one of %s", c.State, strings.Join(states, ", "))
	}
	if !slices.Contains(pulls, c.pull()) {
		return fmt.Errorf("pull %q must be one of %s", c.Pull, strings.Join(pulls, ", "))
	}
	if c.Content != "" && len(c.Files) > 1 {
		return errors.New("content is written to one file, so files can list at most one with it")
	}
	return nil
}

// cli is the shell that picks the engine and makes c() the Compose
// command for it, with the project's own arguments.
func (c Compose) cli() string {
	var base []string
	if c.ProjectName != "" {
		base = append(base, "-p", c.ProjectName)
	}
	for _, f := range c.Files {
		base = append(base, "-f", f)
	}
	for _, f := range c.EnvFiles {
		base = append(base, "--env-file", f)
	}
	for _, p := range c.Profiles {
		base = append(base, "--profile", p)
	}
	b := quoteAll(base)
	// podman compose would hand over to docker-compose when that's
	// installed, whose flags differ, so podman-compose is called by name.
	return pickEngine(c.Engine) + `if [ "$e" = docker ]; then c() { docker compose ` + b + ` "$@"; }; ps="ps -a"
elif command -v podman-compose >/dev/null 2>&1; then c() { podman-compose ` + b + ` "$@"; }; ps=ps
else echo "podman-compose isn't installed on this host; add a package step for it before this one (it's in EPEL on Rocky Linux and RHEL)" >&2; exit 1; fi
`
}

// hashed is the files whose change plans an up.
func (c Compose) hashed() []string {
	files := c.Files
	if len(files) == 0 {
		files = composeDef
	}
	env := c.EnvFiles
	if len(env) == 0 {
		env = []string{".env"}
	}
	return append(slices.Clone(files), env...)
}

// ComposeActual is what Compose reports for the project.
type ComposeActual struct {
	Engine     string
	NoDir      bool
	Hash       string            // of the Compose and env files on the host
	ConfigErr  string            // why compose config failed, if it did
	Defined    []string          // the services the files enable
	Containers map[string]string // service => "running", "done" (exited 0) or "down", the best of its containers
}

func ReadCompose(ctx context.Context, r modules.Runner, c Compose) (ComposeActual, error) {
	if err := c.Validate(); err != nil {
		return ComposeActual{}, err
	}
	script := c.cli() + `echo "$e"
cd -- ` + ssh.Quote(c.ProjectDir) + ` 2>/dev/null || { echo nodir; exit 0; }
sha256sum -- ` + quoteAll(c.hashed()) + ` 2>/dev/null | sha256sum | cut -d' ' -f1
svc=$(c config --services) || { echo bad; exit 0; }
echo ok
printf '%s\n' "$svc"
echo --ps--
c $ps --format json || exit 1
`
	res, err := r.Run(ctx, script, nil)
	if err != nil {
		return ComposeActual{}, err
	}
	if res.ExitCode != 0 {
		return ComposeActual{}, errors.New(strings.TrimSpace(string(res.Stderr) + string(res.Stdout)))
	}
	return parseCompose(string(res.Stdout), string(res.Stderr))
}

func parseCompose(out, stderr string) (ComposeActual, error) {
	lines := strings.SplitN(out, "\n", 4)
	a := ComposeActual{Engine: strings.TrimSpace(lines[0]), Containers: map[string]string{}}
	if len(lines) < 2 || lines[1] == "nodir" {
		a.NoDir = true
		return a, nil
	}
	a.Hash = lines[1]
	if len(lines) < 3 || lines[2] != "ok" {
		a.ConfigErr = strings.TrimSpace(stderr)
		return a, nil
	}
	svcs, ps, _ := strings.Cut(lines[3], "--ps--\n")
	a.Defined = strings.Fields(svcs)
	got, err := parsePS(ps)
	if err != nil {
		return ComposeActual{}, fmt.Errorf("reading %s compose ps: %v", a.Engine, err)
	}
	a.Containers = got
	return a, nil
}

// parsePS reads compose ps --format json: one object a line from docker
// compose, a podman ps array from podman-compose, whose service is only in
// its labels. A container that exited 0 is a one-shot service that's done.
func parsePS(out string) (map[string]string, error) {
	type entry struct {
		Service  string
		State    string
		ExitCode int
		Labels   json.RawMessage // a map from Podman, a string from Docker
	}
	var all []entry
	out = strings.TrimSpace(out)
	if strings.HasPrefix(out, "[") {
		if err := json.Unmarshal([]byte(out), &all); err != nil {
			return nil, err
		}
	} else {
		for _, l := range strings.Split(out, "\n") {
			if l = strings.TrimSpace(l); l == "" {
				continue
			}
			var e entry
			if err := json.Unmarshal([]byte(l), &e); err != nil {
				return nil, err
			}
			all = append(all, e)
		}
	}
	rank := map[string]int{"down": 0, "done": 1, "running": 2}
	got := map[string]string{}
	for _, e := range all {
		if e.Service == "" {
			var labels map[string]string
			_ = json.Unmarshal(e.Labels, &labels)
			e.Service = labels["com.docker.compose.service"]
		}
		if e.Service == "" {
			continue
		}
		st := "down"
		switch {
		case e.State == "running":
			st = "running"
		case e.State == "exited" && e.ExitCode == 0:
			st = "done"
		}
		if old, ok := got[e.Service]; !ok || rank[st] > rank[old] {
			got[e.Service] = st
		}
	}
	return got, nil
}

// Differences lists what about the project differs from c, in words.
// applied is the files' hash at the last apply, "" when there was none.
func (c Compose) Differences(a ComposeActual, applied string) []string {
	if c.state() == "absent" {
		for _, s := range sortedKeys(a.Containers) {
			if len(c.Services) == 0 || slices.Contains(c.Services, s) {
				return []string{"service " + s + " has containers"}
			}
		}
		return nil
	}
	if a.NoDir {
		return []string{"its directory isn't there"}
	}
	var out []string
	if applied != "" && a.Hash != applied {
		out = append(out, "its Compose or env files changed since the last apply")
	}
	if a.ConfigErr != "" {
		return append(out, "compose config fails: "+a.ConfigErr)
	}
	wanted := c.Services
	if len(wanted) == 0 {
		wanted = a.Defined
	}
	for _, s := range wanted {
		switch {
		case !slices.Contains(a.Defined, s):
			out = append(out, "service "+s+" isn't in its Compose files")
		case c.state() == "present" && a.Containers[s] != "running" && a.Containers[s] != "done":
			out = append(out, "service "+s+" isn't running")
		case c.state() == "stopped" && a.Containers[s] == "running":
			out = append(out, "service "+s+" is running")
		}
	}
	if c.RemoveOrphans && c.state() == "present" {
		for _, s := range sortedKeys(a.Containers) {
			if !slices.Contains(a.Defined, s) {
				out = append(out, "orphan service "+s+" has containers")
			}
		}
	}
	return out
}

func sortedKeys(m map[string]string) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	slices.Sort(keys)
	return keys
}

// upArgs are compose up's arguments for engine.
func (c Compose) upArgs(engine string, noStart bool) ([]string, error) {
	args := []string{"up", "-d"}
	if noStart {
		args = append(args, "--no-start")
	}
	if engine == "docker" {
		args = append(args, "--quiet-pull")
		if c.pull() != "policy" {
			args = append(args, "--pull", c.pull())
		}
		if c.Wait && !noStart {
			args = append(args, "--wait")
		}
	} else {
		// podman-compose pulls what's missing, has --pull-always for
		// always, and no way to never pull, wait, or merge env files.
		if c.pull() == "always" {
			args = append(args, "--pull-always")
		}
		if c.pull() == "never" {
			return nil, errors.New(`podman-compose can't be told never to pull; set pull to "missing" or "policy", or use Docker`)
		}
		if c.Wait && !noStart {
			return nil, errors.New("podman-compose has no --wait; unset wait, or use Docker")
		}
		if len(c.EnvFiles) > 1 {
			return nil, errors.New("podman-compose reads only the last --env-file; list one env file, or use Docker")
		}
	}
	if c.RemoveOrphans {
		args = append(args, "--remove-orphans")
	}
	return append(append(args, "--"), c.Services...), nil
}

// ApplyCompose writes Content if it's set and brings the project to its
// state: up for present, created and stopped for stopped, down for absent.
// Volumes stay. It returns the files' hash after.
func ApplyCompose(ctx context.Context, r modules.Runner, c Compose) (string, error) {
	a, err := ReadCompose(ctx, r, c)
	if err != nil {
		return "", err
	}
	var stdin []byte
	script := ""
	if c.Content != "" {
		script = "mkdir -p -- " + ssh.Quote(c.ProjectDir) + " && (umask 077 && cat > " + ssh.Quote(c.file()) + ") && chmod 600 -- " + ssh.Quote(c.file()) + " || exit 1\n"
		stdin = []byte(c.Content)
	}
	script += c.cli() + "cd -- " + ssh.Quote(c.ProjectDir) + " || exit 1\n"
	switch c.state() {
	case "absent":
		if a.NoDir && c.Content == "" {
			return "", nil
		}
		args := []string{"down"}
		if c.RemoveOrphans {
			args = append(args, "--remove-orphans")
		}
		script += "c " + quoteAll(append(append(args, "--"), c.Services...)) + " >/dev/null"
	case "stopped":
		up, err := c.upArgs(a.Engine, true)
		if err != nil {
			return "", err
		}
		script += "c " + quoteAll(up) + " >/dev/null || exit 1\nc " + quoteAll(append([]string{"stop", "--"}, c.Services...)) + " >/dev/null"
	default:
		up, err := c.upArgs(a.Engine, false)
		if err != nil {
			return "", err
		}
		script += "c " + quoteAll(up) + " >/dev/null"
	}
	if err := runWith(ctx, r, "compose project "+c.ProjectDir, script, stdin); err != nil {
		return "", err
	}
	after, err := ReadCompose(ctx, r, c)
	if err != nil {
		return "", err
	}
	if why := c.Differences(after, ""); len(why) > 0 {
		return "", fmt.Errorf("compose project %s isn't as wanted after the change: %s; see %s logs", c.ProjectDir, strings.Join(why, ", "), a.Engine)
	}
	return after.Hash, nil
}

// DeleteCompose runs compose down, which leaves volumes and the files.
func DeleteCompose(ctx context.Context, r modules.Runner, c Compose) error {
	if err := c.Validate(); err != nil {
		return err
	}
	c.State, c.Content = "absent", ""
	_, err := ApplyCompose(ctx, r, c)
	return err
}

func runWith(ctx context.Context, r modules.Runner, what, script string, stdin []byte) error {
	res, err := r.Run(ctx, script, stdin)
	if err != nil {
		return err
	}
	if res.ExitCode != 0 {
		return fmt.Errorf("%s: %s", what, strings.TrimSpace(string(res.Stderr)+string(res.Stdout)))
	}
	return nil
}
