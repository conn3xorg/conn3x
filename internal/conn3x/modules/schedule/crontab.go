// Copyright (c) The Conn3x Authors
// SPDX-License-Identifier: MPL-2.0

package schedule

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"fmt"
	"regexp"
	"slices"
	"strings"

	"github.com/opentofu/opentofu/internal/conn3x/modules"
	"github.com/opentofu/opentofu/internal/conn3x/modules/account"
	"github.com/opentofu/opentofu/internal/conn3x/transport/ssh"
)

// Crontab is the whole of one user's spool crontab, the one crontab -e
// edits: exactly the environment and jobs a crontab step lists.
type Crontab struct {
	User string
	Env  map[string]string
	Jobs []Job
}

// Job is one line of a Crontab, under a comment that names it.
type Job struct{ Name, Schedule, Command string }

var envName = regexp.MustCompile(`^[A-Za-z_][A-Za-z0-9_]*$`)

// jobMark starts the comment Conn3x writes above each job. Lines with it
// are Conn3x's own, and written afresh each time.
const jobMark = "# conn3x: "

// Validate checks a Crontab before anything reaches the host.
func (c Crontab) Validate() error {
	if err := (account.UserSpec{Name: c.User}).Validate(); err != nil {
		return err
	}
	seen := map[string]bool{}
	for _, j := range c.Jobs {
		if !cronName.MatchString(j.Name) {
			return fmt.Errorf("job name %q may only use letters, digits, - and _", j.Name)
		}
		if seen[j.Name] {
			return fmt.Errorf("two jobs are named %q", j.Name)
		}
		seen[j.Name] = true
		if err := validSchedule(j.Schedule); err != nil {
			return fmt.Errorf("job %q: %w", j.Name, err)
		}
		if err := singleLine("job "+j.Name+"'s command", j.Command); err != nil {
			return err
		}
	}
	for k, v := range c.Env {
		if !envName.MatchString(k) {
			return fmt.Errorf("env name %q isn't a variable name", k)
		}
		if strings.ContainsAny(v, "\r\n") {
			return fmt.Errorf("env %s must be a single line", k)
		}
	}
	return nil
}

// line is a job as it's written in the crontab. cron turns an unescaped %
// into a newline, so the command's are escaped, as in cron.d files.
func (j Job) line() string {
	return strings.Join(strings.Fields(j.Schedule), " ") + " " + strings.ReplaceAll(j.Command, "%", `\%`)
}

// Unlisted is a line in the crontab that the step doesn't list.
type Unlisted struct {
	Kind     string // "job", "env" or "unreadable"
	Schedule string // a job's schedule, or an env line's variable name
	Hash     string // sha256 of the line as it is
	Head     string // a job's command up to the first space: never kept in state
}

// String is what state keeps of the line: never the command or a value.
func (u Unlisted) String() string {
	switch u.Kind {
	case "job":
		return u.Schedule + " " + u.Hash
	case "env":
		return "env " + u.Schedule + " " + u.Hash
	}
	return "unreadable " + u.Hash
}

var envLine = regexp.MustCompile(`^\s*([A-Za-z_][A-Za-z0-9_]*)\s*=(.*)$`)

// Want returns the crontab the step means, given the one there now:
//   - comments and blank lines Conn3x didn't write, first, in their order;
//   - then the environment, by name;
//   - then each job, under a comment naming it.
//
// Every other line is returned as unlisted, so a plan can say what goes. A
// line that isn't a job or an environment line Conn3x can read goes too,
// since cron might still run it.
func (c Crontab) Want(current string) (string, []Unlisted) {
	wantEnv := map[string]string{}
	for k, v := range c.Env {
		wantEnv[k] = strings.TrimSpace(v)
	}
	jobs := map[string]bool{}
	for _, j := range c.Jobs {
		jobs[j.line()] = true
	}
	var kept []string
	var gone []Unlisted
	for _, l := range strings.Split(strings.TrimSuffix(current, "\n"), "\n") {
		if current == "" {
			break
		}
		t := strings.TrimSpace(l)
		switch {
		case strings.HasPrefix(t, jobMark):
		case t == "" || strings.HasPrefix(t, "#"):
			kept = append(kept, l)
		case envLine.MatchString(l):
			m := envLine.FindStringSubmatch(l)
			if v, ok := wantEnv[m[1]]; !ok || v != strings.TrimSpace(m[2]) {
				gone = append(gone, Unlisted{Kind: "env", Schedule: m[1], Hash: hashLine(l)})
			}
		default:
			schedule, command, ok := splitJob(t)
			if !ok {
				gone = append(gone, Unlisted{Kind: "unreadable", Hash: hashLine(l)})
				continue
			}
			if !jobs[schedule+" "+command] {
				head, _, _ := strings.Cut(command, " ")
				gone = append(gone, Unlisted{Kind: "job", Schedule: schedule, Hash: hashLine(l), Head: head})
			}
		}
	}
	out := kept
	names := make([]string, 0, len(c.Env))
	for k := range c.Env {
		names = append(names, k)
	}
	slices.Sort(names)
	for _, k := range names {
		out = append(out, k+"="+strings.TrimSpace(c.Env[k]))
	}
	for _, j := range c.Jobs {
		out = append(out, jobMark+j.Name, j.line())
	}
	if len(out) == 0 {
		return "", gone
	}
	return strings.Join(out, "\n") + "\n", gone
}

// splitJob reads a crontab line as a schedule, five fields or a macro, and
// the command after it.
func splitJob(line string) (schedule, command string, ok bool) {
	fields := strings.Fields(line)
	n := 5
	if len(fields) > 0 && strings.HasPrefix(fields[0], "@") {
		n = 1
	}
	if len(fields) <= n || validSchedule(strings.Join(fields[:n], " ")) != nil {
		return "", "", false
	}
	rest := line
	for range n {
		rest = strings.TrimLeft(rest, " \t")
		rest = rest[strings.IndexAny(rest+" ", " \t"):]
	}
	return strings.Join(fields[:n], " "), strings.TrimSpace(rest), true
}

func hashLine(l string) string {
	sum := sha256.Sum256([]byte(l))
	return "sha256:" + base64.RawStdEncoding.EncodeToString(sum[:])
}

// MaxCrontab is the largest crontab ReadCrontab returns.
var MaxCrontab = 1 << 20

// noCrontab is the exit status the scripts give when the host has no
// crontab command.
const noCrontab = 120

// ErrNoCrontab says what to install, rather than "command not found".
var ErrNoCrontab = errors.New("the host has no crontab command; install cron (Debian, Ubuntu) or cronie (Rocky, Fedora, RHEL) in an earlier step")

// crontabCmd runs crontab -u user with args as root, the only way to read
// or write another user's crontab: the crontab command keeps the spool
// file, so nothing here touches a path of the user's.
func crontabCmd(user, args string) string {
	return fmt.Sprintf("command -v crontab >/dev/null 2>&1 || exit %d\nexec crontab -u %s %s", noCrontab, ssh.Quote(user), args)
}

func crontabErr(res ssh.Result, user string) error {
	msg := strings.TrimSpace(string(res.Stderr))
	switch {
	case res.ExitCode == noCrontab:
		return ErrNoCrontab
	case strings.Contains(msg, "must be privileged") || strings.Contains(msg, "Permission denied") || strings.Contains(msg, "not allowed"):
		return fmt.Errorf("changing %s's crontab needs root; set become = true in the ssh block: %s", user, msg)
	case strings.Contains(msg, "unknown") || strings.Contains(msg, "does not exist"):
		return fmt.Errorf("user %s does not exist: %s", user, msg)
	}
	return fmt.Errorf("crontab for %s: %s", user, msg)
}

// ReadCrontab returns user's spool crontab, "" when there's none.
func ReadCrontab(ctx context.Context, r modules.Runner, user string) (string, error) {
	res, err := r.Run(ctx, crontabCmd(user, "-l"), nil)
	if err != nil {
		return "", err
	}
	if res.ExitCode != 0 {
		if strings.Contains(string(res.Stderr), "no crontab for") {
			return "", nil
		}
		return "", crontabErr(res, user)
	}
	if len(res.Stdout) > MaxCrontab {
		return "", fmt.Errorf("%s's crontab is over %d MiB, the most Conn3x reads of it", user, MaxCrontab>>20)
	}
	return string(res.Stdout), nil
}

// WriteCrontab replaces user's crontab with content, or removes it when
// content is empty.
func WriteCrontab(ctx context.Context, r modules.Runner, user, content string) error {
	if content == "" {
		return RemoveCrontab(ctx, r, user)
	}
	res, err := r.Run(ctx, crontabCmd(user, "-"), []byte(content))
	if err != nil {
		return err
	}
	if res.ExitCode != 0 {
		return crontabErr(res, user)
	}
	return nil
}

// RemoveCrontab removes user's crontab; one that isn't there is fine.
func RemoveCrontab(ctx context.Context, r modules.Runner, user string) error {
	res, err := r.Run(ctx, crontabCmd(user, "-r"), nil)
	if err != nil {
		return err
	}
	if res.ExitCode != 0 && !strings.Contains(string(res.Stderr), "no crontab for") {
		return crontabErr(res, user)
	}
	return nil
}
