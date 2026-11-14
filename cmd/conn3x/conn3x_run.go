// Copyright (c) The Conn3x Authors
// SPDX-License-Identifier: MPL-2.0

package main

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"slices"
	"strconv"
	"strings"
	"sync"

	shellwords "github.com/mattn/go-shellwords"
	"github.com/zclconf/go-cty/cty"
	"github.com/zclconf/go-cty/cty/convert"

	"github.com/opentofu/opentofu/internal/command"
	"github.com/opentofu/opentofu/internal/configs"
	"github.com/opentofu/opentofu/internal/conn3x/convert/ansible"
	"github.com/opentofu/opentofu/internal/conn3x/hostpattern"
	"github.com/opentofu/opentofu/internal/conn3x/provider"
	"github.com/opentofu/opentofu/internal/conn3x/termsafe"
)

type runOptions struct {
	inventory, module, task, args, user, keyFile, knownHosts string
	port, forks                                              int
	become, check, json                                      bool
	pattern                                                  string
}

func runCommand() command.Command {
	var o runOptions
	c := command.Command{
		Name:  "run",
		Short: "Run a command or a module on hosts, without a circuit",
		Long: `Runs one command, or one module with its arguments, on every host a pattern matches, the way ansible runs one with -a or -m. Nothing is written to state.

  conn3x run -i inventory.ini 'web*:!web3' -a 'systemctl status nginx'
  conn3x run -i inventory.ini webservers -m service -a 'name=nginx state=started enabled=true' -become
  conn3x run -i inventory.ini all -m package -a 'name=htop' -check

Hosts come from an INI or YAML Ansible inventory, with ansible_host, ansible_port, ansible_user and ansible_ssh_private_key_file, and the group_vars and host_vars beside it. The pattern is -limit's: names and globs split by "," or ":", "!" to leave out, "&" to narrow, "~" for a regular expression, and it matches group names as well as host names.

-a without -m runs a command through the host's shell. With -m, it's a module a step can use, and -a holds its arguments as NAME=VALUE, quoted as a shell would. A module does what it does in a step: on a host that's already in line it changes nothing and says ok. -check stops before changing anything.

-task runs a task file instead: named steps, in order, on each host, stopping a host at its first failure. -a then holds the task's params as NAME=VALUE.

  task "deploy" {
    param "version" {}
    step "pkg" {
      package { name = "myapp-${param.version}" }
    }
    step "start" {
      service {
        name  = "myapp"
        state = "started"
      }
    }
  }

A step's arguments can use param.NAME, host.name and host.vars, the inventory's variables for the host.

Each host is checked against known_hosts, as a plan checks it. Exits 0 when every host succeeded, 2 when any failed, and 1 on errors before any host ran.`,
	}
	c.CommandLine.PositionalArg(&o.pattern, "PATTERN", true)
	c.UsageOverride.Usage = "conn3x [global options] run -i <INVENTORY> [options] <PATTERN> -a <COMMAND>\n       conn3x [global options] run -i <INVENTORY> [options] <PATTERN> -m <MODULE> -a <NAME=VALUE ...>\n       conn3x [global options] run -i <INVENTORY> [options] <PATTERN> -task <FILE> [-a <NAME=VALUE ...>]"
	c.CommandLine.StringVar(&o.inventory, "i", "", "Inventory file, INI or YAML, to take hosts from.")
	c.CommandLine.StringVar(&o.inventory, "inventory", "", "Same as -i.")
	c.CommandLine.StringVar(&o.module, "m", "", "Module to run, such as service or package. Without it, -a is a command.")
	c.CommandLine.StringVar(&o.task, "task", "", "Task file to run: named steps, in order, on each host.")
	c.CommandLine.StringVar(&o.args, "a", "", "The command, or the module's arguments as NAME=VALUE.")
	c.CommandLine.StringVar(&o.user, "user", "", "User to log in as, where the inventory doesn't set ansible_user.")
	c.CommandLine.IntVar(&o.port, "port", 0, "SSH port, where the inventory doesn't set ansible_port. Defaults to 22.")
	c.CommandLine.StringVar(&o.keyFile, "private-key-file", "", "Private key to log in with, where the inventory doesn't set one. Defaults to the SSH agent.")
	c.CommandLine.StringVar(&o.knownHosts, "known-hosts-file", "", "known_hosts file to check hosts against. Defaults to ~/.ssh/known_hosts.")
	c.CommandLine.BoolVar(&o.become, "become", false, "Run as root through sudo.")
	c.CommandLine.BoolVar(&o.check, "check", false, "Say what would change, and change nothing.")
	c.CommandLine.BoolVar(&o.json, "json", false, "Print one JSON object per host instead of lines for people.")
	c.CommandLine.IntVar(&o.forks, "forks", 10, "How many hosts to run on at once.")
	c.Run = func(command.Meta) int { return runRun(context.Background(), o, stdout, os.Stderr) }
	c.GroupID = command.OtherCommandGroup.ID
	return c
}

type runHost struct {
	name    string
	ssh     map[string]cty.Value
	status  string // ok, changed, failed
	message string
	result  provider.RunResult
	vars    map[string]string
	steps   []taskResult // with -task
}

func runRun(ctx context.Context, o runOptions, stdout, stderr io.Writer) int {
	fail := func(format string, a ...any) int {
		fmt.Fprintln(stderr, termsafe.Escape(fmt.Sprintf("Error: "+format, a...)))
		return 1
	}
	if o.inventory == "" {
		return fail("-i is required: conn3x run takes its hosts from an inventory, as in: conn3x run -i inventory.ini all -a uptime")
	}
	if o.args == "" && o.module == "" && o.task == "" {
		return fail("give -a with a command, -m with a module, or -task with a task file")
	}
	if o.task != "" && o.module != "" {
		return fail("give -m or -task, not both")
	}
	pattern, err := hostpattern.Parse(o.pattern)
	if err != nil {
		return fail("%s", err)
	}
	var (
		typ    string
		args   map[string]cty.Value
		task   *runTask
		params cty.Value
	)
	if o.task != "" {
		if task, err = loadTask(o.task); err != nil {
			return fail("%s", err)
		}
		given, err := taskParams(o.args)
		if err != nil {
			return fail("%s", err)
		}
		if params, err = task.paramValues(given); err != nil {
			return fail("%s", err)
		}
	} else {
		module := o.module
		if module == "" {
			module = "command"
		}
		var ok bool
		typ, ok = configs.Conn3xStepModules()[module]
		if !ok || strings.HasPrefix(typ, "conn3x_eos_") {
			return fail("%q isn't a module conn3x run can run", module)
		}
		if args, err = runArgs(ctx, module, typ, o.args, o.module == ""); err != nil {
			return fail("%s", err)
		}
	}

	inv, err := ansible.ReadInventory(o.inventory)
	if err != nil {
		return fail("%s", err)
	}
	groups := map[string][]string{}
	for _, g := range inv.GroupNames() {
		for _, h := range inv.Group(g).Names() {
			groups[h] = append(groups[h], g)
		}
	}
	pattern.Resolve(func(g string) []string {
		if inv.Group(g) == nil {
			return nil
		}
		return inv.Ordered(g)
	})
	all := inv.Group("all")
	var hosts []*runHost
	for _, h := range all.Names() {
		if !pattern.MatchIn(h, groups[h]) {
			continue
		}
		hosts = append(hosts, &runHost{name: h, ssh: o.sshFor(h, all.Vars(h)), vars: all.Vars(h)})
	}
	if len(hosts) == 0 {
		return fail("%q matches no host in %s", o.pattern, o.inventory)
	}

	forks := max(o.forks, 1)
	sem := make(chan struct{}, forks)
	var wg sync.WaitGroup
	for _, h := range hosts {
		wg.Add(1)
		go func() {
			defer wg.Done()
			sem <- struct{}{}
			defer func() { <-sem }()
			if task != nil {
				h.status, h.steps = runTaskOn(ctx, task, params, h.name, h.vars, h.ssh, o.check)
				return
			}
			res, err := provider.RunOnce(ctx, typ, args, h.ssh, o.check)
			h.result = res
			switch {
			case err != nil:
				h.status, h.message = "failed", err.Error()
			case res.Changed && o.check:
				h.status = "would change"
			case res.Changed:
				h.status = "changed"
			default:
				h.status = "ok"
			}
		}()
	}
	wg.Wait()

	code := 0
	for _, h := range hosts {
		if h.status == "failed" {
			code = 2
		}
		if o.json && task != nil {
			line, _ := json.Marshal(map[string]any{"host": h.name, "status": h.status, "steps": h.steps})
			fmt.Fprintln(stdout, string(line))
			continue
		}
		if o.json {
			line, _ := json.Marshal(map[string]any{"host": h.name, "status": h.status, "error": h.message, "stdout": h.result.Stdout, "stderr": h.result.Stderr})
			fmt.Fprintln(stdout, string(line))
			continue
		}
		if task != nil {
			fmt.Fprintln(stdout, termsafe.Escape(h.name+" | "+h.status))
			for _, st := range h.steps {
				line := "  " + st.Step + ": " + st.Status
				if st.Error != "" {
					line += ": " + st.Error
				}
				fmt.Fprintln(stdout, termsafe.Escape(line))
				for _, out := range []string{st.Stdout, st.Stderr} {
					if out = strings.TrimRight(out, "\n"); out != "" {
						fmt.Fprintln(stdout, termsafe.Escape("    "+strings.ReplaceAll(out, "\n", "\n    ")))
					}
				}
			}
			continue
		}
		head := h.name + " | " + h.status
		if h.message != "" {
			head += ": " + h.message
		}
		fmt.Fprintln(stdout, termsafe.Escape(head))
		for _, out := range []string{h.result.Stdout, h.result.Stderr} {
			if out = strings.TrimRight(out, "\n"); out != "" {
				fmt.Fprintln(stdout, termsafe.Escape("  "+strings.ReplaceAll(out, "\n", "\n  ")))
			}
		}
	}
	return code
}

// sshFor is a host's ssh block: the inventory's settings for it, then the
// flags.
func (o runOptions) sshFor(host string, vars map[string]string) map[string]cty.Value {
	ssh := map[string]cty.Value{"host": cty.StringVal(host)}
	if a := vars["ansible_host"]; a != "" && !ansible.Encrypted(a) {
		ssh["host"] = cty.StringVal(a)
	}
	str := func(key, inv, flag string) {
		if v := vars[inv]; v != "" && !ansible.Encrypted(v) {
			ssh[key] = cty.StringVal(v)
		} else if flag != "" {
			ssh[key] = cty.StringVal(flag)
		}
	}
	str("user", "ansible_user", o.user)
	str("private_key_file", "ansible_ssh_private_key_file", o.keyFile)
	if o.knownHosts != "" {
		ssh["known_hosts_file"] = cty.StringVal(o.knownHosts)
	}
	if p, err := strconv.Atoi(vars["ansible_port"]); err == nil {
		ssh["port"] = cty.NumberIntVal(int64(p))
	} else if o.port != 0 {
		ssh["port"] = cty.NumberIntVal(int64(o.port))
	}
	if o.become {
		ssh["become"] = cty.True
	}
	return ssh
}

// taskParams reads -a's NAME=VALUE pairs for -task.
func taskParams(raw string) (map[string]string, error) {
	words, err := shellwords.Parse(raw)
	if err != nil {
		return nil, fmt.Errorf("-a: %w", err)
	}
	out := map[string]string{}
	for _, w := range words {
		name, text, ok := strings.Cut(w, "=")
		if !ok {
			return nil, fmt.Errorf("-a: %q isn't NAME=VALUE", w)
		}
		out[name] = text
	}
	return out, nil
}

// runArgs reads -a: the command itself, or a module's NAME=VALUE pairs,
// split as a shell would split them.
func runArgs(ctx context.Context, module, typ, raw string, asCommand bool) (map[string]cty.Value, error) {
	if asCommand {
		return map[string]cty.Value{"command": cty.StringVal(raw)}, nil
	}
	words, err := shellwords.Parse(raw)
	if err != nil {
		return nil, fmt.Errorf("-a: %w", err)
	}
	p, _ := provider.New()
	block := p.GetProviderSchema(ctx).ResourceTypes[typ].Block
	out := map[string]cty.Value{}
	for _, w := range words {
		name, text, ok := strings.Cut(w, "=")
		attr := block.Attributes[name]
		switch {
		case !ok:
			return nil, fmt.Errorf("-a: %q isn't NAME=VALUE", w)
		case attr == nil || (attr.Computed && !attr.Optional) || slices.Contains([]string{"id", "revision", "in_sync", "on_remove"}, name):
			return nil, fmt.Errorf("-a: %s has no argument %q", module, name)
		}
		v, err := convert.Convert(argValue(text, attr.Type), attr.Type)
		if err != nil {
			return nil, fmt.Errorf("-a: %s: %w", name, err)
		}
		out[name] = v
	}
	return out, nil
}
