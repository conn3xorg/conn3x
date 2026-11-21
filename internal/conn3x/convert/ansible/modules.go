// Copyright (c) The Conn3x Authors
// SPDX-License-Identifier: MPL-2.0

package ansible

import (
	"cmp"
	"fmt"
	"io/fs"
	"math"
	"net/url"
	"os"
	"path"
	"path/filepath"
	"regexp"
	"slices"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/hashicorp/hcl/v2/hclsyntax"
	"github.com/zclconf/go-cty/cty"
	"gopkg.in/yaml.v3"

	"github.com/opentofu/opentofu/internal/conn3x/modules/container"
	"github.com/opentofu/opentofu/internal/conn3x/modules/edit"
	"github.com/opentofu/opentofu/internal/conn3x/modules/fsobj"
	"github.com/opentofu/opentofu/internal/conn3x/modules/kmod"
	"github.com/opentofu/opentofu/internal/conn3x/modules/mysql"
	"github.com/opentofu/opentofu/internal/conn3x/modules/pkg"
	"github.com/opentofu/opentofu/internal/conn3x/modules/repo"
	"github.com/opentofu/opentofu/internal/conn3x/modules/storage"
	"github.com/opentofu/opentofu/internal/conn3x/modules/sudoers"
	"github.com/opentofu/opentofu/internal/conn3x/modules/system"

	gossh "golang.org/x/crypto/ssh"
)

const (
	hclsyntaxComment = hclsyntax.TokenComment
	hclsyntaxIdent   = hclsyntax.TokenIdent
)

// step is one Conn3x step a task becomes.
type step struct {
	module string
	attrs  []attr
	notes  []string
	suffix string // tells apart several steps from one task
	blocks []stepBlock
}

// stepBlock is a block inside a step's module, such as a rule's entry.
type stepBlock struct {
	name  string
	attrs []attr
}

type attr struct {
	key string
	val cty.Value
	raw string // an expression, when set
}

// input reads a task's arguments, remembering which it used so that any it
// didn't stop the conversion.
type input struct {
	mod      string
	role     *role // set while converting a role
	args     map[string]*yaml.Node
	vars     map[string]string
	dir      string
	used     map[string]bool
	problem  string
	loop     bool   // the task loops, so {{ item }} means the current item
	runAs    string // an expression for the user Ansible runs a task as; empty when the play leaves it open
	itemUsed bool
	// factsLater is set when a later task or handler in the play reads facts.
	factsLater bool
	// commaFree lists role defaults used as package names: Ansible splits a
	// name at commas into several packages, so the variable can't hold one.
	commaFree []string
	// pathRules are what each role default used in a path must hold to, so
	// the path is absolute as Ansible's would be: "abs" when it starts the
	// path, "noslash" when it ends a copy or template's dest, where Ansible
	// reads a trailing / as a directory to write into.
	pathRules map[string][]string
	// out holds files a role's task adds to the circuit, kept only if the
	// task converts.
	out map[string][]byte
	// wait is set for a uri task that retries until a status answers.
	wait *uriWait
	// jsonEdits are a copy's json_patch chain on the slurp before it, or
	// jsonWhy why that chain can't convert.
	jsonEdits []jsonEdit
	jsonWhy   string
	// csrs are the play's openssl_csr tasks, by the path each writes.
	csrs map[string]map[string]*yaml.Node
	// env is a command or shell task's environment mapping, if it has one.
	env *yaml.Node
	// itemVar names the role default a loop runs over, whose items the
	// caller sets, so item is held to what a default is held to.
	itemVar string
	// itemMaps are the items of a loop over maps written in the task,
	// whose fields can be read anywhere: each item is checked by itself.
	itemMaps []map[string]string
	// itemFields are the fields read from items that are maps, as
	// item.name: nil for a bare read, which needs the field, or the
	// default a | default('x') gives it.
	itemFields map[string]*string
}

// verbatim lists, by module, the arguments Conn3x uses exactly as Ansible
// does whatever their value. Only there can a role default stay a variable
// for the caller to set; anywhere else the converter proves something about
// the value first, such as that a path is no glob, and can't for one it
// doesn't know.
var verbatim = map[string][]string{
	"copy":            {"content", "owner", "group"},
	"template":        {"owner", "group"},
	"file":            {"owner", "group"},
	"lineinfile":      {"line"},
	"blockinfile":     {"block", "content"},
	"package":         {"name", "pkg"},
	"dnf":             {"name", "pkg"},
	"yum":             {"name", "pkg"},
	"apt":             {"name", "pkg"},
	"service":         {"name"},
	"systemd":         {"name"},
	"systemd_service": {"name"},
	"user":            {"name", "shell"},
	"group":           {"name"},
}

// pathArgs lists, by module, the arguments that are a path on the host.
// A role default can go in one when the path is absolute whatever the
// caller sets, which a validation on the variable makes sure of.
var pathArgs = map[string][]string{
	"copy":        {"dest"},
	"template":    {"dest"},
	"file":        {"path", "dest", "name"},
	"lineinfile":  {"path", "dest", "name"},
	"blockinfile": {"path", "dest", "name"},
}

// pathRef checks a role default name at match i of refs in a path argument
// s, and records what the variable must hold to. "" when it can go there,
// or why not.
func (in *input) pathRef(s string, refs [][]int, i int, name string, values []string) string {
	var rules []string
	// The text before it, with the variables already known filled in, such
	// as a family's server root.
	prefix := jinja.ReplaceAllStringFunc(s[:refs[i][0]], func(m string) string {
		if v, ok := in.vars[jinja.FindStringSubmatch(m)[1]]; ok {
			return v
		}
		return m
	})
	if refs[i][0] == 0 {
		rules = append(rules, "abs")
	} else if !strings.HasPrefix(prefix, "/") {
		return "isn't an absolute path"
	}
	if refs[i][1] == len(s) && (in.mod == "copy" || in.mod == "template") {
		rules = append(rules, "noslash")
	}
	for _, v := range values {
		if !pathOK(v, rules) {
			return fmt.Sprintf("would be %q with the role's own value of %q, which Conn3x and Ansible read differently", s, name)
		}
	}
	if in.pathRules == nil {
		in.pathRules = map[string][]string{}
	}
	in.pathRules[name] = append(in.pathRules[name], rules...)
	return ""
}

// pathOK reports whether v holds to rules.
func pathOK(v string, rules []string) bool {
	if slices.Contains(rules, "abs") && !strings.HasPrefix(v, "/") {
		return false
	}
	return !slices.Contains(rules, "noslash") || !strings.HasSuffix(v, "/")
}

var packageModules = map[string]bool{"package": true, "dnf": true, "yum": true, "apt": true}

func (in *input) has(key string) bool { _, ok := in.args[key]; return ok }

// str returns an argument, with simple {{ var }} references to play vars
// filled in. Anything else in braces is a problem for a person.
func (in *input) str(keys ...string) string {
	for _, k := range keys {
		n, ok := in.args[k]
		if !ok {
			continue
		}
		in.used[k] = true
		if n.Kind != yaml.ScalarNode {
			in.fail(k + " is not a single value")
			return ""
		}
		return in.render(k, n.Value)
	}
	return ""
}

func (in *input) list(key string) []string {
	n, ok := in.args[key]
	if !ok {
		return nil
	}
	in.used[key] = true
	var out []string
	if n.Kind == yaml.ScalarNode {
		// Ansible fills in variables first, then splits at commas.
		for _, s := range strings.Split(in.render(key, n.Value), ",") {
			if s = strings.TrimSpace(s); s != "" {
				out = append(out, s)
			}
		}
		return out
	}
	for _, e := range seq(n) {
		out = append(out, in.render(key, scalar(e)))
	}
	return out
}

func (in *input) bool(key string, def bool) bool {
	if !in.has(key) {
		return def
	}
	return truthy(in.str(key))
}

// ignore marks arguments that change nothing Conn3x would do differently.
func (in *input) ignore(keys ...string) {
	for _, k := range keys {
		in.used[k] = true
	}
}

func (in *input) fail(reason string) {
	if in.problem == "" {
		in.problem = reason
	}
}

// field records item.name, matched as m with itemField's submatches sub,
// as a field the loop reads, with its default if it has one, and returns
// the mark for item.value.name.
func (in *input) field(key, m string, sub []string) string {
	var d *string
	if strings.Contains(m, "default(") {
		d = &sub[2]
		if sub[3] != "" {
			d = &sub[3]
		}
	}
	if old, seen := in.itemFields[sub[1]]; seen && (old == nil) != (d == nil) || seen && old != nil && d != nil && *old != *d {
		in.fail(fmt.Sprintf("%s reads item.%s with a different default from elsewhere in the task", key, sub[1]))
		return m
	}
	if in.itemFields == nil {
		in.itemFields = map[string]*string{}
	}
	in.itemFields[sub[1]] = d
	return refMark("item.value." + sub[1])
}

func (in *input) unused() []string {
	var out []string
	for k := range in.args {
		if !in.used[k] && k != "_raw" {
			out = append(out, k)
		}
	}
	sort.Strings(out)
	return out
}

var jinja = regexp.MustCompile(`\{\{\s*([A-Za-z_][A-Za-z0-9_]*)\s*\}\}`)

// itemField matches {{ item.name }}, or with | default('text').
var itemField = regexp.MustCompile(`\{\{\s*item\.([A-Za-z_][A-Za-z0-9_]*)\s*(?:\|\s*default\(\s*(?:'([^'\\]*)'|"([^"\\]*)")\s*\)\s*)?\}\}`)

func (in *input) render(key, s string) string {
	s = in.role.expandFacts(s)
	inPath := in.role != nil && slices.Contains(pathArgs[in.mod], key)
	if in.loop && (in.itemVar != "" || in.itemMaps != nil) {
		fieldRefs, fieldRef := itemField.FindAllStringIndex(s, -1), -1
		orig := s
		s = itemField.ReplaceAllStringFunc(s, func(m string) string {
			fieldRef++
			sub := itemField.FindStringSubmatch(m)
			in.itemUsed = true
			switch {
			case in.itemMaps != nil:
				return in.field(key, m, sub)
			case len(in.role.lists[in.itemVar]) > 0:
				in.fail(fmt.Sprintf("%s reads item.%s, but %q is a list of plain values", key, sub[1], in.itemVar))
			case inPath && !packageModules[in.mod]:
				// A field in a path holds to what the path needs, in every
				// item the role sets and, by a validation, every one a
				// caller does.
				var values []string
				for _, it := range in.role.maps[in.itemVar] {
					if v, ok := it[sub[1]]; ok {
						values = append(values, v)
					}
				}
				if strings.Contains(m, "default(") {
					values = append(values, sub[2]+sub[3]) // one of them is empty
				}
				if why := in.pathRef(orig, fieldRefs, fieldRef, in.itemVar+"."+sub[1], values); why != "" {
					in.fail(fmt.Sprintf("%s uses item.%s from the role default %q and %s", key, sub[1], in.itemVar, why))
					return m
				}
				return in.field(key, m, sub)
			case !slices.Contains(verbatim[in.mod], key) || packageModules[in.mod]:
				in.fail(fmt.Sprintf("%s uses item.%s from the role default %q, and the converter keeps a default as a variable only where Conn3x uses its value exactly as Ansible does, whatever it is set to; here it would have to check each item first", key, sub[1], in.itemVar))
			default:
				return in.field(key, m, sub)
			}
			return m
		})
	}
	refs, ref := jinja.FindAllStringIndex(s, -1), -1
	out := jinja.ReplaceAllStringFunc(s, func(m string) string {
		ref++
		name := jinja.FindStringSubmatch(m)[1]
		if name == "item" && in.loop && inPath && in.itemVar != "" && in.role.maps[in.itemVar] == nil {
			in.itemUsed = true
			if why := in.pathRef(s, refs, ref, in.itemVar, in.role.lists[in.itemVar]); why != "" {
				in.fail(fmt.Sprintf("%s uses item from the role default %q and %s", key, in.itemVar, why))
				return m
			}
			return itemMark
		}
		if name == "item" && in.loop {
			in.itemUsed = true
			if in.itemMaps != nil {
				in.fail(fmt.Sprintf("%s uses each whole item of the loop, which are maps; read a field, such as item.name", key))
				return m
			}
			if in.role != nil && in.role.maps[in.itemVar] != nil {
				in.fail(fmt.Sprintf("%s uses each whole item of %q, which are maps; read a field, such as item.name", key, in.itemVar))
				return m
			}
			if in.itemVar != "" && !slices.Contains(verbatim[in.mod], key) {
				in.fail(fmt.Sprintf("%s uses item from the role default %q, and the converter keeps a default as a variable only where Conn3x uses its value exactly as Ansible does, whatever it is set to; here it would have to check each item first", key, in.itemVar))
				return m
			}
			if in.itemVar != "" && packageModules[in.mod] {
				in.commaFree = append(in.commaFree, in.itemVar)
			}
			return itemMark
		}
		if v, ok := in.vars[name]; ok {
			return v
		}
		if d := in.role.defaultOrNil(name); d != nil && inPath && !d.boolean {
			if why := in.pathRef(s, refs, ref, name, []string{d.value}); why != "" {
				in.fail(fmt.Sprintf("%s refers to the role default %q and %s", key, name, why))
				return m
			}
			return refMark("var." + name)
		}
		if in.role != nil && in.role.defaults[name] != nil {
			if !slices.Contains(verbatim[in.mod], key) {
				in.fail(fmt.Sprintf("%s refers to the role default %q, and the converter keeps a default as a variable only where Conn3x uses its value exactly as Ansible does, whatever it is set to; here it would have to check the value first", key, name))
				return m
			}
			if in.role.defaults[name].boolean {
				// Ansible prints a boolean the Python way, True or False.
				in.fail(fmt.Sprintf("%s prints the true-or-false role default %q, which Ansible writes as True or False and Conn3x as true or false", key, name))
				return m
			}
			if packageModules[in.mod] {
				in.commaFree = append(in.commaFree, name)
			}
			return refMark("var." + name)
		}
		if in.role != nil && len(in.role.varFiles[name]) > 0 {
			in.fail(fmt.Sprintf("%s refers to %q, which is set in %s, loaded by an include_vars the converter can't translate yet; it's usually set per OS", key, name, joinAnd(in.role.varFiles[name])))
			return m
		}
		what := "a play variable"
		if in.role != nil {
			what = "a role variable"
		}
		in.fail(fmt.Sprintf("%s refers to %q, which isn't %s the converter can fill in", key, name, what))
		return m
	})
	if strings.Contains(out, vaultMark) {
		in.fail(key + " is encrypted with Ansible Vault, which the converter can't read. Move the secret to a SOPS file, such as with ansible-vault view <file> | sops -e --input-type yaml --output-type yaml --age <recipient> /dev/stdin > secrets.sops.yaml, and read it with ephemeral \"conn3x_secrets\" into a write-only argument")
	}
	if strings.Contains(out, "{{") || strings.Contains(out, "{%") {
		in.fail(key + " uses a Jinja expression the converter can't translate")
	}
	return out
}

// mode turns an Ansible mode into four octal digits. An unquoted 644 is
// read the way it was obviously meant, and a symbolic mode that sets every
// class with = has exactly one octal result, so it's read too.
func (in *input) mode(key string) (attr, bool) {
	m := in.str(key)
	if m == "" {
		return attr{}, false
	}
	m = strings.TrimPrefix(m, "0o")
	switch {
	case regexp.MustCompile(`^[0-7]{3}$`).MatchString(m):
		m = "0" + m
	case regexp.MustCompile(`^[0-7]{4}$`).MatchString(m):
	default:
		octal, ok := symbolicMode(m)
		if !ok {
			in.fail(fmt.Sprintf("mode %q is not an octal mode; write it in octal, such as %q", m, "0644"))
			return attr{}, false
		}
		m = octal
	}
	return attr{key: "mode", val: cty.StringVal(m)}, true
}

// symbolicMode converts a symbolic mode such as u=rw,g=r,o=r to octal when
// every class is set with =. Such a mode never reads the file's current
// mode, so it has one octal result; +, -, X, a class copied from another
// (u=g) or an empty who depend on the file or the umask, so they stay for
// review.
func symbolicMode(m string) (string, bool) {
	const (
		classU uint = 1 << iota
		classG
		classO
	)
	var bits, seen uint
	for _, clause := range strings.Split(m, ",") {
		eq := strings.IndexByte(clause, '=')
		if eq <= 0 {
			return "", false
		}
		var classes uint
		for i := 0; i < eq; i++ {
			switch clause[i] {
			case 'a':
				classes |= classU | classG | classO
			case 'u':
				classes |= classU
			case 'g':
				classes |= classG
			case 'o':
				classes |= classO
			default:
				return "", false
			}
		}
		if classes == 0 || classes&seen != 0 {
			return "", false
		}
		seen |= classes

		var perms, special uint
		for i := eq + 1; i < len(clause); i++ {
			switch clause[i] {
			case 'r':
				perms |= 4
			case 'w':
				perms |= 2
			case 'x':
				perms |= 1
			case 's':
				// chmod sets setuid for u and setgid for g, and ignores s
				// on o.
				if classes&classU != 0 {
					special |= 04000
				}
				if classes&classG != 0 {
					special |= 02000
				}
			case 't':
				// chmod sets the sticky bit only when o is in the who.
				if classes&classO != 0 {
					special |= 01000
				}
			default:
				return "", false
			}
		}
		if classes&classU != 0 {
			bits |= perms << 6
		}
		if classes&classG != 0 {
			bits |= perms << 3
		}
		if classes&classO != 0 {
			bits |= perms
		}
		bits |= special
	}
	if seen != classU|classG|classO {
		return "", false
	}
	return fmt.Sprintf("%04o", bits), true
}

// number reads an argument that must be a whole number, such as a uid.
func (in *input) number(key string) attr {
	v := in.str(key)
	n, err := strconv.ParseInt(v, 10, 64)
	if err != nil || !digits.MatchString(v) {
		in.fail(fmt.Sprintf("%s %q is not a whole number", key, v))
	}
	return attr{key: key, val: cty.NumberIntVal(n)}
}

// moduleFile is the expression for the path of a file beside the circuit.
func moduleFile(p string) string { return `"${path.module}/` + quoted(p) + `"` }

// modeNote is the note for a copy or template task without mode. Ansible
// then leaves the mode of a file that's already there; the step sets its
// default, which would open up a file kept at 0600.
func (in *input) modeNote() []string {
	if in.has("mode") {
		return nil
	}
	return []string{"TODO(convert): Set mode if this file isn't meant to be 0644. The task set none, so Ansible left a file that was already there as it was; this step sets 0644."}
}

func s(key, v string) attr { return attr{key: key, val: cty.StringVal(v)} }

// optional adds an attribute when the argument is set.
func (in *input) optional(attrs []attr, to string, from ...string) []attr {
	for _, f := range from {
		if in.has(f) {
			return append(attrs, s(to, in.str(f)))
		}
	}
	return attrs
}

func (in *input) owners(attrs []attr) []attr {
	attrs = in.optional(attrs, "owner", "owner")
	return in.optional(attrs, "group", "group")
}

// state checks the state argument is one of allowed, defaulting to def.
func (in *input) state(def string, allowed ...string) string {
	st := def
	if in.has("state") {
		st = in.str("state")
	}
	for _, a := range allowed {
		if st == a {
			return st
		}
	}
	in.fail(fmt.Sprintf("state %q has no Conn3x equivalent here", st))
	return st
}

// local finds a file the playbook refers to, the way Ansible looks for it.
// A role's files are only looked for in its own sub, since they're copied
// into the circuit.
func (in *input) local(sub, name string) string {
	places := []string{filepath.Join(sub, name), name}
	if in.role != nil {
		if !filepath.IsLocal(name) {
			in.fail(fmt.Sprintf("%s is outside the role's %s/", name, sub))
			return ""
		}
		places = places[:1]
	}
	for _, p := range places {
		if _, err := os.Stat(filepath.Join(in.dir, p)); err == nil {
			// A playbook or role from someone else could link to any file
			// on this machine, to be read into a step or copied to a circuit.
			if !linksStayInside(in.dir, p) {
				in.fail(fmt.Sprintf("%s is outside the playbook's or role's own directory, or is a link to a file that is; copy the file in if it belongs there", p))
				return ""
			}
			return filepath.ToSlash(p)
		}
	}
	if in.role != nil {
		in.fail(fmt.Sprintf("%s was not found in the role's %s/", name, sub))
	} else {
		in.fail(fmt.Sprintf("%s was not found beside the playbook or in %s/", name, sub))
	}
	return ""
}

// linksStayInside reports whether dir/p, with every link followed, is still
// under dir.
func linksStayInside(dir, p string) bool {
	root, err := filepath.EvalSymlinks(dir)
	if err != nil {
		return false
	}
	real, err := filepath.EvalSymlinks(filepath.Join(dir, p))
	if err != nil {
		return false
	}
	rel, err := filepath.Rel(root, real)
	return err == nil && filepath.IsLocal(rel)
}

func one(module string, attrs []attr, notes ...string) ([]step, string) {
	return []step{{module: module, attrs: attrs, notes: notes}}, ""
}

// modules maps Ansible module names to their translations.
var modules = map[string]func(*input) ([]step, string){
	"copy":                    copyModule,
	"synchronize":             synchronizeModule,
	"file":                    fileModule,
	"lineinfile":              lineModule,
	"blockinfile":             blockModule,
	"ini_file":                iniFileModule,
	"replace":                 replaceModule,
	"xml":                     xmlModule,
	"template":                templateModule,
	"package":                 packageModule,
	"dnf":                     packageModule,
	"yum":                     packageModule,
	"apt":                     packageModule,
	"pip":                     pipModule,
	"npm":                     npmModule,
	"service":                 serviceModule,
	"systemd":                 serviceModule,
	"systemd_service":         serviceModule,
	"user":                    userModule,
	"group":                   groupModule,
	"authorized_key":          authorizedKeyModule,
	"known_hosts":             knownHostsModule,
	"pam_limits":              pamLimitsModule,
	"debug":                   debugModule,
	"ping":                    pingModule,
	"setup":                   factsModule("setup", "gather_subset", "gather_timeout", "filter", "fact_path"),
	"service_facts":           factsModule("service_facts"),
	"package_facts":           factsModule("package_facts", "manager", "strategy"),
	"cron":                    cronModule,
	"sysctl":                  sysctlModule,
	"openssl_privatekey":      privateKeyModule,
	"openssh_keypair":         sshKeypairModule,
	"openssl_csr":             csrModule,
	"x509_certificate":        x509Module,
	"postgresql_db":           pgDatabaseModule,
	"htpasswd":                htpasswdModule,
	"postgresql_ext":          pgExtensionModule,
	"postgresql_schema":       pgSchemaModule,
	"postgresql_alter_system": pgSettingModule,
	"postgresql_set":          pgSettingModule,
	"postgresql_pg_hba":       pgHbaModule,
	"postgresql_user":         pgRoleModule,
	"postgresql_privs":        pgPrivsModule,
	"mysql_db":                mysqlDatabaseModule,
	"mysql_user":              mysqlUserModule,
	"mysql_variables":         mysqlVariableModule,
	"hostname":                nameOnly("hostname"),
	"timezone":                nameOnly("timezone"),
	"firewalld":               firewalldModule,
	"ufw":                     ufwModule,
	"seboolean":               sebooleanModule,
	"sefcontext":              sefcontextModule,
	"nmcli":                   nmcliModule,
	"seport":                  seportModule,
	"get_url":                 getURLModule,
	"unarchive":               unarchiveModule,
	"git":                     gitModule,
	"mount":                   mountModule,
	"modprobe":                modprobeModule,
	"kernel_blacklist":        kernelBlacklistModule,
	"sudoers":                 sudoersModule,
	"filesystem":              filesystemModule,
	"parted":                  partedModule,
	"lvg":                     lvgModule,
	"lvol":                    lvolModule,
	"docker_container":        containerModule("docker", "published_ports", "ports", "volumes"),
	"podman_container":        containerModule("podman", "publish", "ports", "volume", "volumes"),
	"command":                 commandModule,
	"shell":                   commandModule,
	"reboot":                  rebootModule,
	"wait_for":                waitForModule,
	"uri":                     uriModule,
	"acl":                     aclModule,
	"selinux":                 selinuxModule,
	"alternatives":            alternativesModule,
	"debconf":                 debconfModule,
	"snap":                    snapModule,
	"flatpak":                 flatpakModule,
	"apt_repository":          aptRepositoryModule,
	"yum_repository":          yumRepositoryModule,
	"locale_gen":              localeGenModule,
	"dpkg_selections":         dpkgSelectionsModule,
	"yum_versionlock":         versionlockModule,

	"win_acl":               winACLModule,
	"win_chocolatey":        winChocolateyModule,
	"win_acl_inheritance":   winACLInheritanceModule,
	"win_command":           winCommandModule,
	"win_ping":              pingModule, // checks the same as ping, and data: crash fails the same way
	"win_copy":              winCopyModule,
	"win_dns_client":        winDNSClientModule,
	"win_domain":            winDomainModule,
	"win_domain_controller": winDCModule,
	"win_domain_group":      winADGroupModule,
	"win_domain_membership": winMembershipModule,
	"win_domain_user":       winADUserModule,
	"win_feature":           winFeatureModule,
	"win_lineinfile":        winLineinfileModule,
	"win_timezone":          winTimezoneModule,
	"win_get_url":           winGetURLModule,
	"win_hostname":          winHostnameModule,
	"win_optional_feature":  winOptionalFeatureModule,
	"win_file":              winFileModule,
	"win_firewall_rule":     winFirewallRuleModule,
	"win_firewall":          winFirewallModule,
	"win_group":             winGroupModule,
	"win_group_membership":  winGroupMembershipModule,
	"win_iis_webapppool":    winIISAppPoolModule,
	"win_iis_website":       winIISWebsiteModule,
	"win_package":           winPackageModule,
	"win_powershell":        winPowershellModule,
	"win_reboot":            winRebootModule,
	"win_updates":           winUpdatesModule,
	"win_regedit":           winRegeditModule,
	"win_scheduled_task":    winScheduledTaskModule,
	"win_service":           winServiceModule,
	"win_share":             winShareModule,
	"win_dns_record":        winDNSRecordModule,
	"win_certificate_store": winCertificateStoreModule,
	"win_shell":             winShellModule,
	"win_template":          winTemplateModule,
	"win_user":              winUserModule,
	"win_user_right":        winUserRightModule,
	"win_wait_for":          winWaitForModule,
	// microsoft.iis, which replaces the community.windows IIS modules.
	"web_app_pool": winIISAppPoolModule,
	"website":      winWebsiteModule,
	// microsoft.ad, which replaces win_domain and its kin. By its full name,
	// as plenty of collections have a module called domain.
	"microsoft.ad.domain":            winDomainModule,
	"microsoft.ad.domain_child":      winChildDomainModule,
	"microsoft.ad.domain_controller": winDCModule,
	"microsoft.ad.group":             winADGroupModule,
	"microsoft.ad.membership":        winMembershipModule,
	"microsoft.ad.ou":                winADOUModule,
	"microsoft.ad.user":              winADUserModule,
}

// exact lists the modules matched by their full name only.
var exact = map[string]bool{
	"microsoft.ad.domain": true, "microsoft.ad.domain_child": true, "microsoft.ad.domain_controller": true, "microsoft.ad.membership": true,
	"microsoft.ad.group": true, "microsoft.ad.ou": true, "microsoft.ad.user": true,
}

// fullNameOnly lists collections whose modules are matched only by their full
// name, as listed in exact: microsoft.ad.user is no Linux user.
var fullNameOnly = []string{"microsoft.ad."}

func copyModule(in *input) ([]step, string) {
	if in.jsonWhy != "" {
		return nil, in.jsonWhy
	}
	if in.jsonEdits != nil {
		return jsonValueSteps(in, in.jsonEdits)
	}
	attrs := []attr{s("path", in.str("dest"))}
	switch {
	case in.has("content"):
		attrs = append(attrs, s("content", in.str("content")))
	case in.has("src"):
		if p := in.local("files", in.str("src")); p != "" {
			attrs = append(attrs, attr{key: "content", raw: "file(" + moduleFile(p) + ")"})
			if in.role != nil {
				in.copy(p)
			}
		}
		if in.has("remote_src") && in.bool("remote_src", false) {
			return nil, "copies a file already on the host (remote_src), which the converter can't translate yet"
		}
	default:
		return nil, "has neither content nor src"
	}
	if m, ok := in.mode("mode"); ok {
		attrs = append(attrs, m)
	}
	if !in.bool("force", true) {
		return nil, "sets force: no, so Ansible writes the file only when it's missing; Conn3x would replace it on every apply"
	}
	if in.has("validate") {
		v, reason := fileValidate(in.str("validate"))
		if reason != "" {
			return nil, reason
		}
		attrs = append(attrs, s("validate", v))
	}
	if in.bool("backup", false) {
		attrs = append(attrs, attr{key: "backup", val: cty.True})
	}
	return one("file", in.owners(attrs), in.modeNote()...)
}

// synchronizeModule turns ansible.posix.synchronize, pushing a directory
// from the controller, into a directory_copy step. rsync copies "src/"'s
// contents into dest, and "src" itself into dest/src; the destination says
// which. What rsync does beyond copying files goes to review.
func synchronizeModule(in *input) ([]step, string) {
	src, dest := in.str("src"), in.str("dest")
	switch {
	case src == "" || dest == "":
		return nil, "needs src and dest"
	case in.str("mode") == "pull":
		return nil, "pulls from the host (mode: pull), which directory_copy doesn't do"
	case in.has("rsync_opts") || in.has("rsync_path") || in.has("set_remote_user") || in.has("private_key"):
		return nil, "passes rsync options or its own connection settings, which the converter can't carry over"
	case in.bool("dirs", false) || in.bool("copy_links", false):
		return nil, "sets dirs or copy_links, which change what rsync copies"
	case in.has("include") || in.has("exclude") || in.has("link_dest"):
		return nil, "filters what it copies (include, exclude or link_dest), which directory_copy can't yet"
	case !strings.HasPrefix(dest, "/"):
		return nil, "has a relative dest, so where it lands depends on the remote user's home"
	}
	local := in.local("files", strings.TrimSuffix(src, "/"))
	if local == "" {
		return nil, "copies " + src + ", which isn't in the playbook's or role's directory"
	}
	if in.role != nil {
		root := filepath.Join(in.dir, local)
		err := filepath.WalkDir(root, func(p string, d fs.DirEntry, err error) error {
			if err != nil || d.IsDir() {
				return err
			}
			if !d.Type().IsRegular() {
				return fmt.Errorf("%s is a link or a special file", p)
			}
			rel, _ := filepath.Rel(in.dir, p)
			in.copy(filepath.ToSlash(rel))
			return nil
		})
		if err != nil {
			return nil, "copies a directory with " + err.Error() + " in it; directory_copy copies regular files only"
		}
	}
	if !strings.HasSuffix(src, "/") {
		dest = strings.TrimSuffix(dest, "/") + "/" + filepath.Base(local)
	}
	attrs := []attr{{key: "source", raw: moduleFile(local)}, s("destination", strings.TrimSuffix(dest, "/"))}
	if in.bool("delete", false) {
		attrs = append(attrs, attr{key: "delete", val: cty.True})
	}
	var notes []string
	if in.bool("archive", true) || in.has("perms") || in.has("owner") || in.has("group") {
		notes = append(notes, "TODO(convert): rsync kept each file's own mode and owner from the controller; directory_copy gives every file one mode (0644 unless you set mode) and one owner. Set them if the files need others.")
	}
	in.ignore("archive", "compress", "recursive", "times", "perms", "owner", "group", "checksum", "verify_host", "use_ssh_args", "delay_updates", "partial", "mode")
	return one("directory_copy", attrs, notes...)
}

// shellSyntax is what a shell reads differently from the plain argument
// list Ansible runs validate as. A newline is whitespace to Ansible's
// shlex, but sh runs the next line as a command of its own.
var shellSyntax = regexp.MustCompile("[|&;<>$`\\\\(){}\\[\\]*?~#\\n\\r]")

// editFileArgs adds what an edit step sets on the file as a whole, as a
// file step does: its mode, owner and group, and validate, the command that
// checks the edited file before it's swapped in.
func (in *input) editFileArgs(attrs []attr) ([]attr, string) {
	if in.bool("backup", false) {
		attrs = append(attrs, attr{key: "backup", val: cty.True})
	}
	if m, ok := in.mode("mode"); ok {
		attrs = append(attrs, m)
	}
	attrs = in.owners(attrs)
	if !in.has("validate") {
		return attrs, ""
	}
	v, why := fileValidate(in.str("validate"))
	if why != "" {
		return nil, why
	}
	return append(attrs, s("validate", v)), ""
}

// fileValidate turns Ansible's validate into a file step's. Ansible splits
// the command into arguments and runs it without a shell, while Conn3x runs
// it through one with %s already quoted, so quotes around %s go and shell
// syntax is left for a person.
func fileValidate(cmd string) (string, string) {
	if !strings.Contains(cmd, "%s") {
		return "", "validate has no %s, the file to check"
	}
	cmd = strings.NewReplacer(`'%s'`, "%s", `"%s"`, "%s").Replace(cmd)
	if shellSyntax.MatchString(cmd) {
		return "", "validate uses shell syntax, which Ansible passes to the command as plain arguments and a Conn3x validate would run"
	}
	return cmd, ""
}

func fileModule(in *input) ([]step, string) {
	path := in.str("path", "dest", "name")
	switch in.state("file", "directory", "link", "file", "absent", "touch") {
	case "directory":
		attrs := []attr{s("path", path)}
		if in.bool("recurse", false) {
			// A numeric mode would give every file a directory's execute
			// bit; a symbolic one says with X which paths get it.
			if m := in.str("mode"); m != "" {
				if !fsobj.IsSymbolic(m) {
					return nil, "sets recurse with a numeric mode, which would make every file under it executable too; give the directory step a symbolic mode, such as \"u=rwX,g=rX,o=\""
				}
				attrs = append(attrs, s("mode", m))
			}
			return one("directory", in.owners(append(attrs, attr{key: "recurse", val: cty.True})))
		}
		if m, ok := in.mode("mode"); ok {
			attrs = append(attrs, m)
		}
		in.ignore("recurse")
		return one("directory", in.owners(attrs))
	case "link":
		if in.has("owner") || in.has("group") || in.has("mode") {
			return nil, "sets owner, group or mode on a link, which a Conn3x link step doesn't manage"
		}
		return one("link", []attr{s("path", path), s("target", in.str("src"))})
	case "absent":
		// Ansible removes whatever is there; a file step refuses anything
		// but a file, so a wrong guess stops the plan instead of deleting.
		return one("file", []attr{s("path", path), s("state", "absent")},
			"Ansible removes whatever is at path, even a directory and everything in it. This step removes a file and stops with an error at anything else: make it a directory or link step if that's what's there.")
	}
	return nil, "changes an existing file's attributes or touches it, which the converter can't translate yet"
}

func editTarget(in *input) []attr {
	attrs := []attr{s("path", in.str("path", "dest", "name"))}
	attrs = in.optional(attrs, "insert_after", "insertafter")
	attrs = in.optional(attrs, "insert_before", "insertbefore")
	if in.has("create") {
		attrs = append(attrs, attr{key: "create", val: cty.BoolVal(in.bool("create", false))})
	}
	if st := in.state("present", "present", "absent"); st != "present" {
		attrs = append(attrs, s("state", st))
	}
	return attrs
}

func lineModule(in *input) ([]step, string) {
	attrs := editTarget(in)
	if in.has("search_string") && (in.has("regexp") || in.has("regex") || in.bool("backrefs", false)) {
		return nil, "sets both search_string and regexp or backrefs, which the lineinfile module refuses"
	}
	if in.bool("backrefs", false) {
		key := "regexp"
		if !in.has(key) {
			key = "regex"
		}
		pattern, line := in.text(key), in.text("line")
		if in.problem != "" {
			return nil, in.problem
		}
		if pattern == "" {
			return nil, "uses backrefs without a regexp"
		}
		if why := unprovableRegexp(pattern); why != "" {
			return nil, why
		}
		tmpl, why := goTemplate(line, regexp.MustCompile(pattern))
		if why != "" {
			return nil, why
		}
		attrs = append(attrs, s("line", tmpl), s("regexp", pattern), attr{key: "backrefs", val: cty.True})
	} else {
		attrs = in.optional(attrs, "line", "line")
		if in.has("search_string") {
			text := in.text("search_string")
			if in.problem != "" {
				return nil, in.problem
			}
			if text == "" {
				return nil, "sets an empty search_string, which matches every line"
			}
			if strings.ContainsAny(text, "\n\r") {
				return nil, "sets a search_string with a line break, which no line of the file can contain"
			}
			attrs = append(attrs, s("regexp", regexp.QuoteMeta(text)))
		} else {
			attrs = in.optional(attrs, "regexp", "regexp", "regex")
		}
	}
	in.ignore("backrefs")
	attrs, why := in.editFileArgs(attrs)
	if why != "" {
		return nil, why
	}
	return one("line", attrs)
}

func blockModule(in *input) ([]step, string) {
	attrs := editTarget(in)
	attrs = append(attrs, s("content", in.str("block", "content")))
	marker := "# {mark} ANSIBLE MANAGED BLOCK"
	if in.has("marker") {
		marker = in.str("marker")
	}
	attrs = append(attrs, s("marker", marker))
	attrs = in.optional(attrs, "marker_begin", "marker_begin")
	attrs = in.optional(attrs, "marker_end", "marker_end")
	attrs, why := in.editFileArgs(attrs)
	if why != "" {
		return nil, why
	}
	return one("block", attrs, "Keeps Ansible's marker, so the block it already wrote is the one Conn3x manages.")
}

func templateModule(in *input) ([]step, string) {
	if in.role == nil {
		in.ignore("src", "dest", "mode", "owner", "group")
		return nil, "renders a Jinja template; rewrite it in templatefile syntax (${var}, %{ if }) and use a template step"
	}
	attrs := []attr{s("destination", in.str("dest"))}
	p := in.local("templates", in.str("src"))
	if p == "" {
		return nil, in.problem
	}
	source, vars, why := in.template(p)
	if why != "" {
		return nil, "renders a template that " + why + "; rewrite it in templatefile syntax (${var}, %{ if }) and use a template step"
	}
	attrs = append([]attr{{key: "source", raw: moduleFile(source)}}, attrs...)
	if vars != "" {
		attrs = append(attrs, attr{key: "vars", raw: vars})
	}
	if m, ok := in.mode("mode"); ok {
		attrs = append(attrs, m)
	}
	if !in.bool("force", true) {
		return nil, "sets force: no, so Ansible writes the file only when it's missing; Conn3x would replace it on every apply"
	}
	if in.has("validate") {
		v, reason := fileValidate(in.str("validate"))
		if reason != "" {
			return nil, reason
		}
		attrs = append(attrs, s("validate", v))
	}
	if in.bool("backup", false) {
		attrs = append(attrs, attr{key: "backup", val: cty.True})
	}
	return one("template", in.owners(attrs), in.modeNote()...)
}

func packageModule(in *input) ([]step, string) {
	names := in.list("name")
	if len(names) == 0 {
		names = in.list("pkg")
	}
	st := in.state("present", "present", "installed", "latest", "absent", "removed")
	if alias, ok := map[string]string{"installed": "present", "removed": "absent"}[st]; ok {
		st = alias
	}
	var notes []string
	if in.has("update_cache") {
		in.ignore("update_cache", "cache_valid_time")
		notes = append(notes, "update_cache dropped: Conn3x refreshes the package lists when a package isn't found.")
	}
	var steps []step
	for _, n := range names {
		// A glob or '*' names no single package and cannot validate as a
		// package step. Leave the whole task for review, not a partial list.
		// Names holding \x00 are marks for variables and loop items, filled in
		// later. A name render couldn't fill already has its reason in
		// in.problem, which is more use than this one.
		if in.problem == "" && !strings.Contains(n, "\x00") && !pkg.ValidName(n) {
			if n == "*" {
				return nil, "upgrades every package, which Conn3x leaves to a scheduled job rather than a step"
			}
			return nil, "package name " + strconv.Quote(n) + " cannot be a package step"
		}
		attrs := []attr{s("name", n)}
		if st != "present" {
			attrs = append(attrs, s("state", st))
		}
		// apt's install_recommends and dnf's install_weak_deps are one setting.
		for _, k := range []string{"install_recommends", "install_weak_deps"} {
			if in.has(k) {
				attrs = append(attrs, attr{key: "install_recommends", val: cty.BoolVal(in.bool(k, true))})
			}
		}
		steps = append(steps, step{module: "package", attrs: attrs, notes: notes, suffix: n})
		notes = nil
	}
	if len(steps) == 0 && notes != nil && !in.has("state") {
		// Only update_cache: nothing for a step to do.
		return []step{{notes: notes}}, ""
	}
	if len(steps) == 0 {
		return nil, "names no package"
	}
	return steps, ""
}

func serviceModule(in *input) ([]step, string) {
	attrs := []attr{s("name", in.str("name"))}
	if in.has("state") {
		st := in.state("", "started", "stopped")
		attrs = append(attrs, s("state", st))
	}
	if in.has("enabled") {
		attrs = append(attrs, attr{key: "enabled", val: cty.BoolVal(in.bool("enabled", false))})
	}
	if in.has("masked") {
		attrs = append(attrs, attr{key: "masked", val: cty.BoolVal(in.bool("masked", false))})
	}
	var notes []string
	if in.has("daemon_reload") {
		in.ignore("daemon_reload")
		notes = append(notes, "daemon_reload dropped: Conn3x reloads systemd when a unit file changed.")
	}
	return one("service", attrs, notes...)
}

func userModule(in *input) ([]step, string) {
	in.state("present", "present")
	attrs := []attr{s("name", in.str("name"))}
	if in.has("uid") {
		attrs = append(attrs, in.number("uid"))
	}
	attrs = in.optional(attrs, "group", "group")
	if in.has("groups") {
		appendGroups := in.bool("append", false)
		var vals []cty.Value
		for _, g := range in.list("groups") {
			vals = append(vals, cty.StringVal(g))
		}
		if len(vals) > 0 {
			attrs = append(attrs, attr{key: "groups", val: cty.ListVal(vals)})
			if appendGroups {
				attrs = append(attrs, attr{key: "append", val: cty.True})
			}
		}
	}
	attrs = in.optional(attrs, "home", "home")
	attrs = in.optional(attrs, "shell", "shell")
	attrs = in.optional(attrs, "comment", "comment")
	if in.has("system") {
		attrs = append(attrs, attr{key: "system", val: cty.BoolVal(in.bool("system", false))})
	}
	if in.has("password_lock") {
		attrs = append(attrs, attr{key: "locked", val: cty.BoolVal(in.bool("password_lock", false))})
	}
	// expires is seconds since 1970; Ansible compares only the date it
	// falls on in UTC, and a negative one removes the expiry.
	if in.has("expires") {
		e := in.str("expires")
		f, err := strconv.ParseFloat(e, 64)
		if in.problem == "" && (err != nil || math.IsNaN(f) || math.IsInf(f, 0)) {
			return nil, fmt.Sprintf("sets expires %q, which isn't a number of seconds since 1970", e)
		}
		date := ""
		if f >= 0 {
			date = time.Unix(int64(math.Floor(f)), 0).UTC().Format(time.DateOnly)
		}
		attrs = append(attrs, s("expires", date))
	}
	// createhome is Ansible's older name for create_home.
	for _, k := range []string{"create_home", "createhome"} {
		if in.has(k) && !in.bool(k, true) {
			attrs = append(attrs, attr{key: "create_home", val: cty.False})
			break
		}
	}
	in.ignore("create_home", "createhome")
	// Ansible's password is already a crypt hash. It's never read, so it
	// can't end up in the output.
	var notes []string
	if in.has("password") {
		note := "TODO(convert): Set password_hash_wo from an ephemeral variable holding the task's password, which is a crypt hash. It isn't copied here."
		if in.str("update_password") == "on_create" {
			note += " Add password_on_create = true, as the task had update_password: on_create."
		}
		notes = append(notes, note)
	}
	in.ignore("password", "update_password")
	return one("user", attrs, notes...)
}

func groupModule(in *input) ([]step, string) {
	in.state("present", "present")
	attrs := []attr{s("name", in.str("name"))}
	if in.has("gid") {
		attrs = append(attrs, in.number("gid"))
	}
	if in.has("system") {
		attrs = append(attrs, attr{key: "system", val: cty.BoolVal(in.bool("system", false))})
	}
	return one("group", attrs)
}

func authorizedKeyModule(in *input) ([]step, string) {
	in.state("present", "present")
	raw := in.str("key")
	exclusive := in.has("exclusive") && in.bool("exclusive", false)
	opts, hasOpts := in.str("key_options"), in.has("key_options")
	if hasOpts && exclusive {
		return nil, "sets key_options with exclusive, which the converter can't translate yet"
	}
	key := s("key", raw)
	switch {
	case !strings.Contains(raw, "\x00"):
		// Ansible drops blank lines and # comments from key first.
		var lines []string
		for _, l := range strings.Split(raw, "\n") {
			if l = strings.TrimSpace(l); l != "" && !strings.HasPrefix(l, "#") {
				lines = append(lines, l)
			}
		}
		if len(lines) > 1 && !exclusive {
			return nil, fmt.Sprintf("gives %d keys without exclusive, and an authorized_key step takes one; make a task for each key", len(lines))
		}
		if hasOpts {
			for i, l := range lines {
				line, err := keyWithOptions(opts, l)
				if err != nil {
					return nil, err.Error()
				}
				lines[i] = line
			}
			key = s("key", strings.Join(lines, "\n"))
		}
	case hasOpts:
		// A key from a variable may hold any number of lines, so the
		// options go on each through an expression that skips blank and #
		// lines, as Ansible does. Options already on such a key stay.
		key = keyOptionsExpr(opts, raw)
	}
	attrs := []attr{s("user", in.str("user")), key}
	// exclusive keeps only this task's keys, which key may hold one per
	// line, as Ansible reads it.
	if exclusive {
		attrs = append(attrs, attr{key: "exclusive", val: cty.True})
	}
	return one("authorized_key", attrs)
}

// keyOptionsExpr puts opts on each key line of a key from a variable,
// skipping blank and # lines.
func keyOptionsExpr(opts, raw string) attr {
	return attr{key: "key", raw: fmt.Sprintf(`join("\n", [for k in split("\n", %s) : "%s ${trimspace(k)}" if trimspace(k) != "" && !startswith(trimspace(k), "#")])`, markTemplate(raw), quoted(opts))}
}

// keyWithOptions is a key line with opts in place of any options it had:
// Ansible's key_options replaces them rather than adding to them, and two
// option fields aren't a key line.
func keyWithOptions(opts, line string) (string, error) {
	pub, comment, _, _, err := gossh.ParseAuthorizedKey([]byte(line))
	if err != nil {
		return "", fmt.Errorf("sets key_options, and key %q isn't a public key the converter can read", line)
	}
	out := strings.TrimSpace(string(gossh.MarshalAuthorizedKey(pub)))
	if comment != "" {
		out += " " + comment
	}
	return opts + " " + out, nil
}

var cronName = regexp.MustCompile(`[^A-Za-z0-9_-]+`)

func cronModule(in *input) ([]step, string) {
	in.state("present", "present")
	if in.has("cron_file") {
		return nil, "writes to a named cron_file, which the converter can't translate yet"
	}
	schedule := ""
	if in.has("special_time") {
		schedule = "@" + in.str("special_time")
	} else {
		var fields []string
		for _, k := range []string{"minute", "hour", "day", "month", "weekday"} {
			v := "*"
			if in.has(k) {
				v = in.str(k)
			}
			fields = append(fields, v)
		}
		schedule = strings.Join(fields, " ")
	}
	name := strings.Trim(cronName.ReplaceAllString(in.str("name"), "-"), "-")
	attrs := []attr{s("name", name), s("schedule", schedule), s("command", in.str("job"))}
	attrs = in.optional(attrs, "user", "user")
	return one("cron", attrs, "Conn3x keeps the job in /etc/cron.d rather than the user's crontab.",
		fmt.Sprintf("TODO(convert): Delete the \"#Ansible: %s\" job Ansible left in the user's crontab, or it runs twice.", in.str("name")))
}

func sysctlModule(in *input) ([]step, string) {
	in.state("present", "present")
	in.ignore("reload", "sysctl_set")
	name := in.str("name")
	attrs := []attr{s("name", name), s("value", in.str("value"))}
	if !in.has("sysctl_file") {
		return one("sysctl", attrs)
	}
	// The step keeps the setting in a file of its own, and sets the running
	// value, so the task converts; the old file still holds its line.
	file, ours := in.str("sysctl_file"), "its own file in /etc/sysctl.d"
	if !strings.ContainsAny(name+file, "\x00{") {
		ours = system.Sysctl{Key: name}.Path()
	}
	if strings.ContainsAny(file, "\x00{") {
		file = "the file the task names"
	}
	return one("sysctl", attrs, fmt.Sprintf("Ansible kept this setting in %s; a sysctl step keeps it in %s. Take the line out of %s: at boot these files are applied in name order, so a later file's value wins.", file, ours, file))
}

// htpasswdModule converts community.general.htpasswd. The password is never
// read, so it can't end up in the output.
func htpasswdModule(in *input) ([]step, string) {
	if st := in.str("state"); st != "" && st != "present" {
		return nil, fmt.Sprintf("has state %q; the htpasswd step takes its line out only when the step is removed with on_remove = \"delete\"", st)
	}
	attrs := []attr{s("path", in.str("path", "dest", "destfile")), s("name", in.str("name", "username"))}
	// Ansible creates a missing file unless create is false.
	if in.bool("create", true) {
		attrs = append(attrs, attr{key: "create", val: cty.True})
	}
	if m, ok := in.mode("mode"); ok {
		attrs = append(attrs, m)
	}
	attrs = in.optional(attrs, "owner", "owner")
	attrs = in.optional(attrs, "group", "group")
	scheme := in.str("hash_scheme", "crypt_scheme")
	if scheme == "" {
		scheme = "apr_md5_crypt"
	}
	notes := []string{"TODO(convert): Set password_wo from an ephemeral variable. The task's password isn't copied here."}
	if scheme != "bcrypt" {
		notes = append(notes, "Conn3x hashes the password with bcrypt, where the task used "+scheme+". Apache reads bcrypt; check that anything else reading this file does too.")
	}
	in.ignore("password")
	return one("htpasswd", attrs, notes...)
}

// pgDatabaseModule converts community.postgresql.postgresql_db. The step
// talks to the local server through psql, so connection options stay for a
// person.
func pgDatabaseModule(in *input) ([]step, string) {
	if st := in.str("state"); st != "" && st != "present" {
		return nil, fmt.Sprintf("has state %q; postgresql_database only makes a database, and drops it only when the step is removed with on_remove = \"delete\"", st)
	}
	if k := in.pgUnmodelled("template", "lc_collate", "lc_ctype", "icu_locale", "locale_provider", "conn_limit", "tablespace", "comment", "force", "target", "target_opts", "maintenance_db"); k != "" {
		return nil, "sets " + k + ", which postgresql_database doesn't offer yet"
	}
	attrs := []attr{s("name", in.str("name", "db", "datname"))}
	attrs = in.optional(attrs, "owner", "owner")
	attrs = in.optional(attrs, "encoding", "encoding")
	return one("postgresql_database", attrs)
}

// pgExtensionModule converts community.postgresql.postgresql_ext.
func pgExtensionModule(in *input) ([]step, string) {
	if st := in.str("state"); st != "" && st != "present" {
		return nil, fmt.Sprintf("has state %q; postgresql_extension only makes an extension, and drops it only when the step is removed with on_remove = \"delete\"", st)
	}
	if in.str("version") == "latest" {
		return nil, "has version latest, which postgresql_extension doesn't offer yet; give the version to install"
	}
	if k := in.pgUnmodelled("comment"); k != "" {
		return nil, "sets " + k + ", which postgresql_extension doesn't offer yet"
	}
	in.ignore("trust_input")
	attrs := []attr{s("name", in.str("ext", "name")), s("database", in.str("login_db", "db"))}
	attrs = in.optional(attrs, "schema", "schema")
	attrs = in.optional(attrs, "version", "version")
	if in.bool("cascade", false) {
		attrs = append(attrs, attr{key: "cascade", val: cty.True})
	}
	return one("postgresql_extension", attrs)
}

// pgSchemaModule converts community.postgresql.postgresql_schema.
// Ansible's login_db defaults to postgres, so a task without one makes the
// schema there, and so does the step.
func pgSchemaModule(in *input) ([]step, string) {
	if st := in.str("state"); st != "" && st != "present" {
		return nil, fmt.Sprintf("has state %q; postgresql_schema only makes a schema, and drops it only when the step is removed with on_remove = \"delete\"", st)
	}
	if in.bool("cascade_drop", false) {
		return nil, "sets cascade_drop, and postgresql_schema drops a schema only without CASCADE"
	}
	if k := in.pgUnmodelled("comment"); k != "" {
		return nil, "sets " + k + ", which postgresql_schema doesn't offer yet"
	}
	in.ignore("trust_input", "cascade_drop")
	database := in.str("login_db", "db", "database")
	if database == "" {
		database = "postgres"
	}
	attrs := []attr{s("name", in.str("name", "schema")), s("database", database)}
	attrs = in.optional(attrs, "owner", "owner")
	return one("postgresql_schema", attrs)
}

// pgSettingModule converts community.postgresql.postgresql_alter_system,
// and postgresql_set, which it replaced: param or name, and value.
// Settings are server-wide, so login_db makes no difference.
func pgSettingModule(in *input) ([]step, string) {
	value := in.str("value")
	if value == "_RESET" {
		return nil, "resets the setting; postgresql_setting does that only when the step is removed with on_remove = \"delete\""
	}
	if in.has("reset") {
		return nil, "sets reset, which postgresql_setting doesn't offer; remove the step with on_remove = \"delete\" instead"
	}
	if k := in.pgUnmodelled(); k != "" {
		return nil, "sets " + k + ", which postgresql_setting doesn't offer yet"
	}
	in.ignore("trust_input", "login_db", "db")
	return one("postgresql_setting", []attr{s("name", in.str("param", "name")), s("value", value)})
}

// pgAttributes are the role attributes postgresql_role's attributes sets
// exactly.
var pgAttributes = []string{"SUPERUSER", "CREATEDB", "CREATEROLE", "REPLICATION", "BYPASSRLS"}

// pgRoleModule converts community.postgresql.postgresql_user.
func pgRoleModule(in *input) ([]step, string) {
	if st := in.str("state"); st != "" && st != "present" {
		return nil, fmt.Sprintf("has state %q; postgresql_role only makes a role, and drops it only when the step is removed with on_remove = \"delete\"", st)
	}
	if in.has("encrypted") && !in.bool("encrypted", true) {
		return nil, "stores the password unencrypted; postgresql_role always sends a SCRAM-SHA-256 verifier"
	}
	if in.bool("no_password_changes", false) {
		return nil, "sets no_password_changes, so Ansible sets the password only on a new role; postgresql_role sets it whenever password_wo changes"
	}
	if k := in.pgUnmodelled("expires", "conn_limit", "comment", "groups", "fail_on_user", "trust_input"); k != "" {
		return nil, "sets " + k + ", which postgresql_role doesn't offer yet"
	}
	attrs := []attr{s("name", in.str("name", "user"))}
	var notes []string
	if in.has("priv") {
		grants, why := pgPriv(in.str("db"), in.str("priv"))
		if why != "" {
			return nil, why
		}
		attrs = append(attrs, attr{key: "database_grants", val: grants})
		notes = append(notes, "database_grants is the role's whole list: privileges it has on other databases are revoked, where Ansible only added these.")
	}
	in.ignore("db")
	if in.has("role_attr_flags") {
		login, set, why := pgFlags(in.str("role_attr_flags"))
		if why != "" {
			return nil, why
		}
		if login != nil {
			attrs = append(attrs, attr{key: "login", val: cty.BoolVal(*login)})
		}
		if set != nil {
			vals := []cty.Value{}
			for _, a := range set {
				vals = append(vals, cty.StringVal(a))
			}
			v := cty.ListValEmpty(cty.String)
			if len(vals) > 0 {
				v = cty.ListVal(vals)
			}
			attrs = append(attrs, attr{key: "attributes", val: v})
		}
	}
	if in.has("password") {
		notes = append(notes, "TODO(convert): Set password_wo from an ephemeral variable. The task's password isn't copied here.")
	}
	// Never read, so a password can't end up in the output.
	in.ignore("password", "encrypted", "no_password_changes")
	return one("postgresql_role", attrs, notes...)
}

// pgPriv reads postgresql_user's priv, such as "CONNECT/TEMP", on db as
// database_grants. A table:PRIV element is for one table, which
// postgresql_role doesn't grant on, and stays for a person.
func pgPriv(db, priv string) (cty.Value, string) {
	if db == "" {
		return cty.NilVal, "sets priv without db, which Ansible needs to know where to grant"
	}
	var privs []cty.Value
	for _, p := range strings.Split(strings.ToUpper(priv), "/") {
		if strings.Contains(p, ":") {
			return cty.NilVal, "grants privileges on a single table with priv, which postgresql_role doesn't manage; table_grants covers every table in a schema"
		}
		for _, one := range strings.Split(p, ",") {
			switch one = strings.TrimSpace(one); one {
			case "ALL", "ALL PRIVILEGES":
				privs = append(privs, cty.StringVal("CONNECT"), cty.StringVal("CREATE"), cty.StringVal("TEMPORARY"))
			case "TEMP", "TEMPORARY":
				privs = append(privs, cty.StringVal("TEMPORARY"))
			case "CONNECT", "CREATE":
				privs = append(privs, cty.StringVal(one))
			case "":
			default:
				return cty.NilVal, fmt.Sprintf("grants %s with priv, which isn't a database privilege postgresql_role grants", one)
			}
		}
	}
	if len(privs) == 0 {
		return cty.NilVal, "sets an empty priv"
	}
	return cty.MapVal(map[string]cty.Value{db: cty.ListVal(privs)}), ""
}

// pgPrivsModule leaves community.postgresql.postgresql_privs for a person:
// its grants belong on the role's own step, which owns the whole list.
func pgPrivsModule(in *input) ([]step, string) {
	if in.has("grant_option") {
		return nil, "sets grant_option, which Conn3x doesn't manage yet"
	}
	return nil, "grants privileges in a task of its own; Conn3x keeps a role's grants on its postgresql_role step, as database_grants, schema_grants and table_grants, so move them there"
}

// pgUnmodelled names the first of keys the task sets, or a login_ or
// connection option, which the steps don't take: they run psql on the host.
func (in *input) pgUnmodelled(keys ...string) string {
	keys = append(keys, "login_host", "login_user", "login_password", "login_unix_socket", "port", "session_role", "ssl_mode", "ca_cert", "ssl_cert", "ssl_key", "connect_params")
	for _, k := range keys {
		if in.has(k) {
			return k
		}
	}
	return ""
}

// pgFlags reads role_attr_flags. Ansible changes only the attributes it
// names, but postgresql_role's attributes is exact, so the flags convert to
// it only when they name all five, each as X or NOX. LOGIN or NOLOGIN sets
// login. Anything else is left for a person.
func pgFlags(flags string) (login *bool, set []string, why string) {
	named := map[string]bool{}
	for _, f := range strings.Split(strings.ToUpper(flags), ",") {
		f = strings.TrimSpace(f)
		on := !strings.HasPrefix(f, "NO")
		base := strings.TrimPrefix(f, "NO")
		switch {
		case f == "":
		case base == "LOGIN":
			login = &on
		case slices.Contains(pgAttributes, base):
			named[base] = on
		default:
			return nil, nil, fmt.Sprintf("sets the role flag %s, which postgresql_role doesn't offer yet", f)
		}
	}
	if len(named) == 0 {
		return login, nil, ""
	}
	if len(named) < len(pgAttributes) {
		return nil, nil, "names only some of SUPERUSER, CREATEDB, CREATEROLE, REPLICATION and BYPASSRLS in role_attr_flags; Ansible leaves the rest as they are, but postgresql_role's attributes is the exact list, so name all five, each as X or NOX, or set attributes by hand"
	}
	set = []string{}
	for _, a := range pgAttributes {
		if named[a] {
			set = append(set, a)
		}
	}
	return login, set, ""
}

// mysqlUnmodelled names the first of keys the task sets, or a login_ or
// connection option, which the steps don't take: they use the client on the
// server's socket.
func (in *input) mysqlUnmodelled(keys ...string) string {
	keys = append(keys, "login_host", "login_user", "login_password", "login_port", "login_unix_socket", "config_file", "client_cert", "client_key", "ca_cert", "check_hostname", "check_implicit_admin", "config_overrides_defaults")
	for _, k := range keys {
		if in.has(k) {
			return k
		}
	}
	return ""
}

// mysqlDatabaseModule converts community.mysql.mysql_db.
func mysqlDatabaseModule(in *input) ([]step, string) {
	if st := in.str("state"); st != "" && st != "present" {
		return nil, fmt.Sprintf("has state %q; mysql_database only makes a database, and drops it only when the step is removed with on_remove = \"delete\"", st)
	}
	if k := in.mysqlUnmodelled("target", "single_transaction", "quick", "ignore_tables", "hex_blob", "force", "master_data", "skip_lock_tables", "dump_extra_args", "use_shell", "unsafe_login_password", "restrict_config_file", "chdir", "pipefail", "sql_log_bin"); k != "" {
		return nil, "sets " + k + ", which mysql_database doesn't offer yet"
	}
	attrs := []attr{s("name", in.str("name", "db"))}
	attrs = in.optional(attrs, "charset", "encoding")
	attrs = in.optional(attrs, "collation", "collation")
	return one("mysql_database", attrs)
}

// mysqlUserModule converts community.mysql.mysql_user. Only database-level
// privileges convert, since those are what the step's grants holds.
// mysqlVariableModule converts mysql_variables, from community.mysql or
// ansible.mysql: variable, value and mode.
func mysqlVariableModule(in *input) ([]step, string) {
	if k := in.mysqlUnmodelled(); k != "" {
		return nil, "sets " + k + ", which mysql_variable doesn't offer yet"
	}
	if !in.has("value") {
		return nil, "has no value, so Ansible only reads the variable"
	}
	name, value := in.str("variable"), in.str("value")
	if in.problem != "" {
		return nil, in.problem
	}
	attrs := []attr{s("name", name), s("value", value)}
	switch mode := in.str("mode"); mode {
	case "", "global":
	case "persist", "persist_only":
		attrs = append(attrs, s("mode", mode))
	default:
		return nil, fmt.Sprintf("has mode %q, which Ansible refuses", mode)
	}
	var notes []string
	if sizeSuffixed.MatchString(strings.TrimSpace(value)) {
		notes = append(notes, "Ansible sends "+value+" to SET as a string, which MySQL refuses for a number; mysql_variable turns the suffix into bytes, so this step sets it where the task failed.")
	}
	return one("mysql_variable", attrs, notes...)
}

// sizeSuffixed is a value with a K, M, G or T suffix, as my.cnf takes it.
var sizeSuffixed = regexp.MustCompile(`^(?i)\d+[KMGT]$`)

func mysqlUserModule(in *input) ([]step, string) {
	if st := in.str("state"); st != "" && st != "present" {
		return nil, fmt.Sprintf("has state %q; mysql_user only makes a user, and drops it only when the step is removed with on_remove = \"delete\"", st)
	}
	if in.bool("append_privs", false) {
		return nil, "sets append_privs, so Ansible adds to the user's privileges; mysql_user's grants is the exact list, so list them all or set grants by hand"
	}
	if in.has("encrypted") && in.bool("encrypted", false) {
		return nil, "gives the password already hashed; mysql_user takes the password itself in password_wo"
	}
	if st := in.str("update_password"); st != "" && st != "always" {
		return nil, fmt.Sprintf("has update_password %q; mysql_user sets the password whenever password_wo changes", st)
	}
	if k := in.mysqlUnmodelled("host_all", "plugin", "plugin_hash_string", "plugin_auth_string", "salt", "resource_limits", "tls_requires", "subtract_privs", "column_case_sensitive", "password_expire", "password_expire_interval", "attributes", "force_context", "session_vars", "sql_log_bin"); k != "" {
		return nil, "sets " + k + ", which mysql_user doesn't offer yet"
	}
	name := in.str("name", "user")
	if l := strings.ToLower(name); l == "root" || strings.HasPrefix(l, "mysql.") || strings.HasPrefix(l, "mariadb.") {
		return nil, fmt.Sprintf("manages %s, an account the server itself needs, which mysql_user won't touch", name)
	}
	attrs := []attr{s("name", name)}
	attrs = in.optional(attrs, "host", "host")
	var notes []string
	if in.has("priv") {
		grants, why := in.mysqlGrants()
		if why != "" {
			return nil, why
		}
		attrs = append(attrs, attr{key: "grants", val: grants})
		notes = append(notes, "Ansible also took away global and table privileges priv didn't list; mysql_user changes only database-level ones.")
	}
	if in.has("password") {
		notes = append(notes, "TODO(convert): Set password_wo from an ephemeral variable. The task's password isn't copied here.")
	}
	// Never read, so a password can't end up in the output.
	in.ignore("password", "encrypted", "update_password", "append_privs")
	return one("mysql_user", attrs, notes...)
}

// mysqlGrants reads priv, as "app.*:ALL/logs.*:SELECT,INSERT" or as a map of
// the same, into grants. *.*:USAGE, which grants nothing, is dropped.
func (in *input) mysqlGrants() (cty.Value, string) {
	n := in.args["priv"]
	in.used["priv"] = true
	var parts [][2]string
	switch n.Kind {
	case yaml.ScalarNode:
		for _, p := range strings.Split(in.render("priv", n.Value), "/") {
			on, privs, ok := strings.Cut(p, ":")
			if !ok {
				return cty.NilVal, fmt.Sprintf("has a priv part %q with no privileges after a colon", p)
			}
			parts = append(parts, [2]string{on, privs})
		}
	case yaml.MappingNode:
		for i := 0; i+1 < len(n.Content); i += 2 {
			parts = append(parts, [2]string{in.render("priv", n.Content[i].Value), in.render("priv", n.Content[i+1].Value)})
		}
	default:
		return cty.NilVal, "has a priv that isn't a string or a map"
	}
	grants := map[string]cty.Value{}
	for _, p := range parts {
		on, privs := strings.TrimSpace(p[0]), strings.ToUpper(strings.TrimSpace(p[1]))
		if on == "*.*" && privs == "USAGE" {
			continue
		}
		db, table, _ := strings.Cut(on, ".")
		db = strings.Trim(db, "`")
		if table != "*" || db == "*" || db == "" {
			return cty.NilVal, fmt.Sprintf("grants on %s; mysql_user's grants holds only database-level privileges, as app.*", on)
		}
		if _, dup := grants[db]; dup {
			return cty.NilVal, fmt.Sprintf("grants on %s twice", on)
		}
		var vals []cty.Value
		for _, pr := range strings.Split(privs, ",") {
			pr = strings.Join(strings.Fields(pr), " ")
			if pr == "ALL" {
				pr = "ALL PRIVILEGES"
			}
			if !slices.Contains(mysql.Privileges, pr) {
				return cty.NilVal, fmt.Sprintf("grants %s on %s, which mysql_user doesn't offer yet", pr, on)
			}
			vals = append(vals, cty.StringVal(pr))
		}
		if len(vals) > 1 && slices.ContainsFunc(vals, func(v cty.Value) bool { return v.AsString() == "ALL PRIVILEGES" }) {
			return cty.NilVal, fmt.Sprintf("grants ALL with others on %s; mysql_user needs ALL PRIVILEGES alone", on)
		}
		grants[db] = cty.ListVal(vals)
	}
	if len(grants) == 0 {
		return cty.MapValEmpty(cty.List(cty.String)), ""
	}
	return cty.MapVal(grants), ""
}

func nameOnly(module string) func(*input) ([]step, string) {
	return func(in *input) ([]step, string) {
		in.ignore("use")
		return one(module, []attr{s("name", in.str("name"))})
	}
}

func firewalldModule(in *input) ([]step, string) {
	in.state("enabled", "enabled")
	if !in.bool("permanent", false) || !in.bool("immediate", false) {
		return nil, "doesn't set both permanent and immediate; Conn3x always changes both"
	}
	attrs := in.optional(nil, "zone", "zone")
	attrs = in.optional(attrs, "service", "service")
	attrs = in.optional(attrs, "port", "port")
	attrs = in.optional(attrs, "rich_rule", "rich_rule")
	attrs = in.optional(attrs, "source", "source")
	return one("firewalld", attrs)
}

// ufwSettingsModule converts a ufw task that changes ufw itself: state
// enabled or disabled, and default (or policy) with direction, which
// Ansible takes as incoming when it's left out.
func ufwSettingsModule(in *input) ([]step, string) {
	var attrs []attr
	switch st := in.str("state"); st {
	case "":
	case "enabled", "disabled":
		attrs = append(attrs, attr{key: "enabled", val: cty.BoolVal(st == "enabled")})
	default:
		return nil, fmt.Sprintf("has state %s, which ufw_settings doesn't do; use a command step", st)
	}
	if p := in.str("default", "policy"); p != "" {
		dir := in.str("direction")
		switch dir {
		case "", "incoming":
			dir = "incoming"
		case "outgoing", "routed":
		default:
			return nil, fmt.Sprintf("sets default with direction %s, which Ansible refuses; it takes incoming, outgoing or routed", dir)
		}
		attrs = append(attrs, s("default_"+dir, p))
	}
	if in.has("logging") {
		return nil, "sets logging, which ufw_settings doesn't offer yet"
	}
	if len(attrs) == 0 {
		return nil, "changes ufw itself in a way ufw_settings doesn't cover"
	}
	return one("ufw_settings", attrs)
}

func ufwModule(in *input) ([]step, string) {
	if !in.has("rule") {
		return ufwSettingsModule(in)
	}
	port := in.str("port", "to_port")
	if in.has("proto") {
		if p := in.str("proto"); p != "any" {
			port += "/" + p
		}
	}
	attrs := []attr{s("action", in.str("rule")), s("port", port)}
	attrs = in.optional(attrs, "from", "from_ip", "from", "src")
	return one("ufw", attrs)
}

func sebooleanModule(in *input) ([]step, string) {
	if !in.bool("persistent", false) {
		return nil, "sets the boolean until reboot only; Conn3x always makes it persistent"
	}
	return one("selinux_boolean", []attr{s("name", in.str("name")), {key: "value", val: cty.BoolVal(in.bool("state", false))}})
}

func sefcontextModule(in *input) ([]step, string) {
	in.state("present", "present")
	in.ignore("reload")
	return one("selinux_fcontext", []attr{s("target", in.str("target")), s("setype", in.str("setype"))})
}

// seportModule converts community.general.seport for one port or range.
// seport fails on a host without SELinux unless ignore_selinux_state is
// set, where selinux_port does nothing; that and the rest get a note.
func seportModule(in *input) ([]step, string) {
	in.state("present", "present")
	ports := in.list("ports")
	if len(ports) != 1 {
		return nil, "names " + strconv.Itoa(len(ports)) + " ports; a selinux_port step takes one port or range, so give each its own step"
	}
	// local: true reads local rules only, as the step does; without it,
	// seport also counts the policy's, which here means one local rule.
	in.ignore("reload", "ignore_selinux_state", "local")
	attrs := []attr{s("port", ports[0]), s("protocol", in.str("proto")), s("setype", in.str("setype"))}
	return one("selinux_port", attrs, "On a host without SELinux this step does nothing, where seport fails unless ignore_selinux_state is set.")
}

// xmlModule converts community.general.xml for one element's text or one
// attribute, set or taken out, as xml_value owns. The xpath must be the
// part of XPath xml_value reads; namespaces, children, counting and
// printing go to review.
func xmlModule(in *input) ([]step, string) {
	for _, key := range []string{"namespaces", "add_children", "set_children", "content"} {
		if in.has(key) {
			return nil, "sets " + key + ", which an xml_value step doesn't do"
		}
	}
	// pretty_print rewrites the whole file, where the step keeps every byte
	// it doesn't own; the others read or count rather than set.
	for _, key := range []string{"pretty_print", "count", "print_match", "insertbefore", "insertafter"} {
		if in.bool(key, false) {
			return nil, "sets " + key + ", which an xml_value step doesn't do"
		}
	}
	if in.has("create_if_missing") && !in.bool("create_if_missing", true) {
		return nil, "sets create_if_missing: no, and an xml_value step adds a missing last element"
	}
	in.ignore("pretty_print", "count", "print_match", "insertbefore", "insertafter", "create_if_missing", "input_type", "huge_tree", "strip_cdata_tags")
	xpath := in.str("xpath")
	st := in.state("present", "present", "absent")
	attrs := []attr{s("path", in.str("path", "dest", "file"))}
	if st == "absent" {
		if in.has("attribute") || in.has("value") {
			return nil, "sets attribute or value with state: absent"
		}
		attrs = append(attrs, s("xpath", xpath), s("state", "absent"))
	} else {
		if !in.has("value") {
			return nil, "sets no value, so it only checks the path is there"
		}
		if a := in.str("attribute"); a != "" {
			xpath += "/@" + a
		}
		attrs = append(attrs, s("xpath", xpath), s("value", in.str("value")))
	}
	if err := (edit.XMLValue{XPath: xpath, Value: "x", State: edit.State(st)}).Validate(); err != nil {
		return nil, "has an xpath an xml_value step can't read: " + err.Error()
	}
	attrs, why := in.editFileArgs(attrs)
	if why != "" {
		return nil, why
	}
	return one("xml_value", attrs, "Ansible sets every element the xpath matches; an xml_value step needs exactly one, and an apply that finds several says how to pick one.")
}

// partedModule converts community.general.parted for one partition made
// or kept. Ansible's label defaults to msdos, where the step's is gpt, so
// the step is told; its default start, 0%, isn't a size the step takes.
func partedModule(in *input) ([]step, string) {
	if st := in.state("info", "present"); st != "present" {
		return nil, "has state " + st + ", and only state: present makes a partition step"
	}
	if !in.has("number") {
		return nil, "names no partition number, which a partition step needs"
	}
	for _, key := range []string{"name", "fs_type"} {
		if in.has(key) {
			return nil, "sets " + key + ", which a partition step doesn't"
		}
	}
	if t := in.str("part_type"); t != "" && t != "primary" {
		return nil, "makes a " + t + " partition; a partition step makes primary ones"
	}
	if a := in.str("align"); a != "" && a != "optimal" {
		return nil, "sets align " + a + ", and a partition step aligns optimally"
	}
	if !in.has("part_start") {
		return nil, "sets no part_start, so Ansible starts at 0%; a partition step needs a start in MiB, GiB or TiB, such as 1MiB"
	}
	in.ignore("unit", "unit_preserve_case")
	n, err := strconv.Atoi(in.str("number"))
	if err != nil {
		return nil, "has a number that isn't a whole number"
	}
	p := storage.Partition{Device: in.str("device"), Number: n, Start: in.str("part_start"), End: cmp.Or(in.str("part_end"), "100%"), Label: cmp.Or(in.str("label"), "msdos")}
	if err := p.Validate(); err != nil {
		return nil, "can't be a partition step: " + err.Error()
	}
	attrs := []attr{s("device", p.Device), {key: "number", val: cty.NumberIntVal(int64(n))}, s("start", p.Start), s("end", p.End), s("label", p.Label)}
	if in.has("flags") {
		vals := []cty.Value{}
		for _, f := range in.list("flags") {
			vals = append(vals, cty.StringVal(f))
		}
		v := cty.ListValEmpty(cty.String)
		if len(vals) > 0 {
			v = cty.ListVal(vals)
		}
		attrs = append(attrs, attr{key: "flags", val: v})
	}
	if in.bool("resize", false) {
		attrs = append(attrs, attr{key: "resize", val: cty.True})
	}
	return one("partition", attrs)
}

func getURLModule(in *input) ([]step, string) {
	sum := in.str("checksum")
	if !strings.HasPrefix(sum, "sha256:") {
		return nil, "has no sha256 checksum; Conn3x downloads only what it can verify"
	}
	attrs := []attr{s("url", in.str("url")), s("dest", in.str("dest")), s("sha256", strings.TrimPrefix(sum, "sha256:"))}
	if m, ok := in.mode("mode"); ok {
		attrs = append(attrs, m)
	}
	return one("download", in.owners(attrs))
}

func unarchiveModule(in *input) ([]step, string) {
	if !in.bool("remote_src", false) {
		return nil, "unpacks a file from the controller; download it first, then use an archive step"
	}
	if !in.has("creates") {
		return nil, "has no creates guard; Conn3x needs one to know when the archive is unpacked"
	}
	return one("archive", []attr{s("src", in.str("src")), s("dest", in.str("dest")), s("creates", in.str("creates"))})
}

func gitModule(in *input) ([]step, string) {
	attrs := []attr{s("repo", in.str("repo")), s("dest", in.str("dest"))}
	attrs = in.optional(attrs, "ref", "version")
	if in.has("depth") {
		attrs = append(attrs, in.number("depth"))
	}
	// A git step always checks out with --force, which is force: true.
	if in.bool("force", false) {
		return one("git", attrs)
	}
	return one("git", attrs, "Ansible stops when the checkout has local changes; a git step discards changes to tracked files.")
}

func mountModule(in *input) ([]step, string) {
	in.state("mounted", "mounted")
	attrs := []attr{s("path", in.str("path", "name")), s("src", in.str("src")), s("fstype", in.str("fstype"))}
	attrs = in.optional(attrs, "opts", "opts")
	// These are fstab's dump and fsck pass fields, which the step writes as
	// they are; dropping them left data disks never checked at boot.
	for _, k := range []string{"dump", "passno"} {
		if in.has(k) {
			attrs = append(attrs, in.number(k))
		}
	}
	return one("mount", attrs)
}

func modprobeModule(in *input) ([]step, string) {
	st := in.state("present", "present", "absent")
	// Ansible's persistent defaults to disabled, which leaves the boot files
	// alone; the step's default writes them.
	persistent := "disabled"
	if in.has("persistent") {
		persistent = in.str("persistent")
	}
	m := kmod.Module{Name: in.str("name"), Params: strings.Fields(in.str("params")), Absent: st == "absent"}
	switch {
	case persistent == "disabled":
	case persistent == "present" && !m.Absent, persistent == "absent" && m.Absent:
		m.Persistent = true
	default:
		return nil, fmt.Sprintf("sets persistent: %s with state: %s, which the modprobe step can't do in one step", persistent, st)
	}
	if err := m.Validate(); err != nil {
		return nil, err.Error()
	}
	attrs := []attr{s("name", m.Name)}
	if len(m.Params) > 0 {
		vals := make([]cty.Value, len(m.Params))
		for i, p := range m.Params {
			vals[i] = cty.StringVal(p)
		}
		attrs = append(attrs, attr{key: "params", val: cty.ListVal(vals)})
	}
	if m.Absent {
		attrs = append(attrs, s("state", "absent"))
	}
	if !m.Persistent {
		attrs = append(attrs, attr{key: "persistent", val: cty.False})
	}
	return one("modprobe", attrs)
}

// kernelBlacklistModule converts community.general.kernel_blacklist, which
// keeps one "blacklist <name>" line in a file under modprobe.d. A line step
// does exactly that, so the task becomes one, in the module's default file
// unless blacklist_file names another. The module writes the file when it's
// missing, which create covers.
func kernelBlacklistModule(in *input) ([]step, string) {
	name := in.str("name")
	if in.problem != "" {
		return nil, in.problem
	}
	if name == "" {
		return nil, "has no name"
	}
	if strings.ContainsAny(name, "\n\r") {
		return nil, fmt.Sprintf("has the name %q, which is not one line", name)
	}
	path := "/etc/modprobe.d/blacklist-ansible.conf"
	if in.has("blacklist_file") {
		path = in.str("blacklist_file")
		if in.problem != "" {
			return nil, in.problem
		}
		if path == "" {
			return nil, "sets an empty blacklist_file"
		}
	}
	attrs := []attr{
		s("path", path),
		s("line", "blacklist "+name),
		s("regexp", kernelBlacklistRegexp(name)),
		{key: "create", val: cty.True},
	}
	if in.state("present", "present", "absent") == "absent" {
		attrs = append(attrs, s("state", "absent"))
	}
	return one("line", attrs)
}

// kernelBlacklistRegexp is the pattern a kernel_blacklist task's line step
// matches: blacklist, whitespace, then the name, and nothing else on the line.
// The module strips a line before matching it, so a hand-written "  blacklist
// nouveau " counts as blacklisted for Ansible; the leading and trailing \s*
// keep the step seeing the same lines, which is what state: absent needs to
// remove one the module would have removed. A leading # is still not matched,
// since # isn't whitespace. The name is escaped so a . or a + matches only
// itself.
func kernelBlacklistRegexp(name string) string {
	return `^\s*blacklist\s+` + regexp.QuoteMeta(name) + `\s*$`
}

// dpkgSelectionsModule turns hold and install into a package_hold step.
// deinstall and purge mark a package for removal, which a hold doesn't.
func dpkgSelectionsModule(in *input) ([]step, string) {
	h := pkg.Hold{Name: in.str("name")}
	switch sel := in.str("selection"); sel {
	case "hold":
		h.Held = true
	case "install":
	default:
		return nil, fmt.Sprintf("selection %q marks the package for removal; use a package step with state = \"absent\"", sel)
	}
	return holdSteps(in, []string{h.Name}, h.Held)
}

// versionlockModule turns each locked name into a package_hold step.
func versionlockModule(in *input) ([]step, string) {
	return holdSteps(in, in.list("name"), in.state("present", "present", "absent") == "present")
}

func holdSteps(in *input, names []string, held bool) ([]step, string) {
	var steps []step
	for _, n := range names {
		// yum_versionlock takes versions and wildcards, as in
		// httpd-0:2.4.57-2.el9; package_hold holds the installed version.
		if strings.ContainsAny(n, ":*?[") {
			return nil, fmt.Sprintf("%s has a version or wildcard: package_hold takes a name only and holds the installed version", n)
		}
		if !strings.Contains(n, "${") {
			if err := (pkg.Hold{Name: n}).Validate(); err != nil {
				return nil, err.Error()
			}
		}
		attrs := []attr{s("name", n)}
		if !held {
			attrs = append(attrs, s("state", "released"))
		}
		steps = append(steps, step{module: "package_hold", attrs: attrs, suffix: n})
	}
	if len(steps) == 0 {
		return nil, "names no package"
	}
	return steps, ""
}

// aclModule converts one ACL entry. Ansible's state defaults to query,
// which reads and changes nothing.
func aclModule(in *input) ([]step, string) {
	if in.has("entry") {
		return nil, "sets entry, the old one-string form; give it etype, entity and permissions instead"
	}
	st := in.state("query", "present", "absent")
	for key, keep := range map[string]string{"recursive": "false", "recurse": "false", "follow": "true", "use_nfsv4_acls": "false", "recalculate_mask": "default"} {
		if in.has(key) && in.str(key) != keep && truthy(in.str(key)) != truthy(keep) {
			return nil, "sets " + key + ", and the acl step owns one entry on one path, as POSIX ACLs"
		}
	}
	attrs := []attr{s("path", in.str("path")), s("etype", in.str("etype"))}
	attrs = in.optional(attrs, "entity", "entity")
	if in.has("permissions") {
		p := strings.ReplaceAll(in.str("permissions"), "-", "")
		if strings.Trim(p, "rwx") != "" {
			return nil, "sets permissions " + in.str("permissions") + "; the acl step takes r, w and x"
		}
		attrs = append(attrs, s("permissions", p))
	}
	if in.has("default") && truthy(in.str("default")) {
		attrs = append(attrs, attr{key: "default", val: cty.True})
	}
	if st == "absent" {
		attrs = append(attrs, s("state", "absent"))
	}
	return one("acl", attrs)
}

// debconfModule presets one answer. A password is never copied: the step
// gets a TODO to set value_wo from an ephemeral variable.
func debconfModule(in *input) ([]step, string) {
	if !in.has("question") && !in.has("setting") && !in.has("selection") {
		return nil, "only names a package, which lists its answers, and debconf sets one"
	}
	if in.has("unseen") && truthy(in.str("unseen")) {
		return nil, "sets unseen, and debconf marks every answer it sets as seen"
	}
	vt := in.str("vtype")
	if vt == "seen" {
		return nil, "has vtype seen, which only flags the question, and debconf sets answers"
	}
	attrs := []attr{s("name", in.str("name", "pkg")), s("question", in.str("question", "setting", "selection")), s("vtype", vt)}
	var notes []string
	switch vt {
	case "password":
		in.ignore("value")
		notes = append(notes, "TODO(convert): Set value_wo from an ephemeral variable. The task's password isn't copied here.")
	case "boolean":
		attrs = append(attrs, s("value", strconv.FormatBool(truthy(in.str("value")))))
	default:
		attrs = append(attrs, s("value", in.str("value")))
	}
	return one("debconf", attrs, notes...)
}

// selinuxModule sets the mode; disabling takes more than the config file.
func selinuxModule(in *input) ([]step, string) {
	st := in.state("", "enforcing", "permissive")
	if c := in.str("configfile"); c != "" && c != "/etc/selinux/config" {
		return nil, "uses the config file " + c + ", and selinux_mode keeps the mode in /etc/selinux/config"
	}
	if in.has("update_kernel_param") && truthy(in.str("update_kernel_param")) {
		return nil, "sets update_kernel_param, and selinux_mode doesn't change boot parameters"
	}
	var notes []string
	if in.has("policy") {
		in.ignore("policy")
		notes = append(notes, "policy dropped: selinux_mode leaves SELINUXTYPE as it is.")
	}
	return one("selinux_mode", []attr{s("mode", st)}, notes...)
}

// alternativesModule selects a path; the other states and slave links have
// no step yet.
func alternativesModule(in *input) ([]step, string) {
	in.state("selected", "selected")
	if in.has("subcommands") {
		return nil, "sets subcommands, and the alternatives step has no slave links"
	}
	attrs := in.optional([]attr{s("name", in.str("name")), s("path", in.str("path"))}, "link", "link")
	if in.has("priority") {
		attrs = append(attrs, in.number("priority"))
	}
	return one("alternatives", attrs)
}

// snapModule installs or removes each named snap; enabling, disabling,
// options and dangerous installs have no step yet.
func snapModule(in *input) ([]step, string) {
	st := in.state("present", "present", "absent")
	for _, k := range []string{"options", "dangerous"} {
		if in.has(k) {
			return nil, "sets " + k + ", which the snap step doesn't have"
		}
	}
	names := in.list("name")
	channel := in.str("channel")
	classic := in.bool("classic", false)
	if in.problem != "" {
		return nil, in.problem
	}
	if len(names) == 0 {
		return nil, "names no snap"
	}
	var steps []step
	for _, n := range names {
		attrs := []attr{s("name", n)}
		if st == "absent" {
			attrs = append(attrs, s("state", st))
		}
		if channel != "" {
			attrs = append(attrs, s("channel", channel))
		}
		if classic {
			attrs = append(attrs, attr{key: "classic", val: cty.True})
		}
		steps = append(steps, step{module: "snap", attrs: attrs, suffix: n})
	}
	return steps, ""
}

// flatpakModule installs each name from its remote; refs and .flatpakref
// URLs have no step yet.
func flatpakModule(in *input) ([]step, string) {
	if why := exactTask(in); why != "" {
		return nil, why
	}
	st := in.state("present", "present", "latest", "absent")
	if e := in.str("executable"); in.has("executable") && e != "flatpak" {
		return nil, fmt.Sprintf("runs %q; a flatpak step runs the host's flatpak", e)
	}
	if in.bool("no_dependencies", false) {
		return nil, "sets no_dependencies, which a flatpak step doesn't have"
	}
	names := in.list("name")
	if len(names) == 0 {
		return nil, "names no app"
	}
	var steps []step
	for _, n := range names {
		if strings.ContainsAny(n, "/:") {
			return nil, fmt.Sprintf("names %q, a ref or URL; a flatpak step takes an application ID such as org.gnome.Calculator", n)
		}
		attrs := in.optional([]attr{s("name", n)}, "remote", "remote")
		attrs = in.optional(attrs, "method", "method")
		if st != "present" {
			attrs = append(attrs, s("state", st))
		}
		steps = append(steps, step{module: "flatpak", attrs: attrs, suffix: n})
	}
	return steps, in.problem
}

func sudoersModule(in *input) ([]step, string) {
	in.state("present", "present")
	// validation: Conn3x always checks with visudo.
	in.ignore("validation")
	if p := in.str("sudoers_path"); p != "" && p != "/etc/sudoers.d" {
		return nil, "writes to " + p + "; the sudoers step writes to /etc/sudoers.d"
	}
	for _, k := range []string{"setenv", "noexec"} {
		if in.bool(k, false) {
			return nil, "sets " + k + ", which the sudoers step doesn't have yet"
		}
	}
	// Ansible's sudoers defaults nopassword to true; the step's default is false.
	r := sudoers.Rule{Name: in.str("name"), User: in.str("user"), Group: in.str("group"), Commands: in.list("commands"), RunAs: in.str("runas"), Host: in.str("host"), NoPassword: in.bool("nopassword", true)}
	if err := r.Validate(); err != nil {
		return nil, err.Error()
	}
	vals := make([]cty.Value, len(r.Commands))
	for i, c := range r.Commands {
		vals[i] = cty.StringVal(c)
	}
	attrs := []attr{s("name", r.Name)}
	if r.User != "" {
		attrs = append(attrs, s("user", r.User))
	} else {
		attrs = append(attrs, s("group", r.Group))
	}
	attrs = append(attrs, attr{key: "commands", val: cty.ListVal(vals)})
	attrs = in.optional(attrs, "runas", "runas")
	attrs = in.optional(attrs, "host", "host")
	if r.NoPassword {
		attrs = append(attrs, attr{key: "nopassword", val: cty.True})
	}
	return one("sudoers", attrs)
}

func filesystemModule(in *input) ([]step, string) {
	in.state("present", "present")
	fs := storage.Filesystem{Device: in.str("dev"), Type: in.str("fstype", "type"), Opts: strings.Fields(in.str("opts")), Resize: in.bool("resizefs", false), Force: in.bool("force", false)}
	if err := fs.Validate(); err != nil {
		return nil, err.Error()
	}
	attrs := []attr{s("device", fs.Device), s("type", fs.Type)}
	if len(fs.Opts) > 0 {
		vals := make([]cty.Value, len(fs.Opts))
		for i, o := range fs.Opts {
			vals[i] = cty.StringVal(o)
		}
		attrs = append(attrs, attr{key: "opts", val: cty.ListVal(vals)})
	}
	if fs.Resize {
		attrs = append(attrs, attr{key: "resize", val: cty.True})
	}
	if fs.Force {
		attrs = append(attrs, attr{key: "force", val: cty.True})
		return one("filesystem", attrs, "TODO(convert): force = true lets this step make its file system over another one, erasing it, on every apply. Take it off once the hosts have the file system.")
	}
	return one("filesystem", attrs)
}

func lvgModule(in *input) ([]step, string) {
	in.state("present", "present")
	// force only matters to Ansible when it removes a group.
	in.ignore("force")
	g := storage.VolumeGroup{Name: in.str("vg"), PVs: in.list("pvs")}
	if err := g.Validate(); err != nil {
		return nil, err.Error()
	}
	vals := make([]cty.Value, len(g.PVs))
	for i, pv := range g.PVs {
		vals[i] = cty.StringVal(pv)
	}
	return one("lvm_volume_group", []attr{s("name", g.Name), {key: "pvs", val: cty.ListVal(vals)}},
		"Ansible's lvg also takes a physical volume that isn't in pvs out of the group; Conn3x leaves it in.")
}

func lvolModule(in *input) ([]step, string) {
	in.state("present", "present")
	size := in.str("size")
	if strings.HasPrefix(size, "+") || strings.HasPrefix(size, "-") {
		return nil, "sets a size relative to the volume's current one, " + size + ", which would change it on every play; set the size it should be"
	}
	l := storage.LogicalVolume{VG: in.str("vg"), Name: in.str("lv"), Size: size, Force: in.bool("force", false)}
	if err := l.Validate(); err != nil {
		return nil, err.Error()
	}
	// shrink only matters with force, which Conn3x's force covers.
	if in.has("shrink") && !in.bool("shrink", true) {
		l.Force = false
	}
	attrs := []attr{s("vg", l.VG), s("name", l.Name), s("size", l.Size)}
	var notes []string
	if in.bool("resizefs", false) {
		notes = append(notes, fmt.Sprintf("TODO(convert): resizefs grew the file system with the volume. Add a filesystem step for /dev/%s/%s after this one, with resize = true.", l.VG, l.Name))
	}
	if l.Force {
		attrs = append(attrs, attr{key: "force", val: cty.True})
		notes = append(notes, "TODO(convert): force = true lets this step shrink the volume, destroying what's past the new end, on every apply. Take it off once the hosts have their size.")
	}
	return one("lvm_logical_volume", attrs, notes...)
}

// containerModule translates docker_container and podman_container, whose
// port and volume arguments go by different names.
func containerModule(engine string, keys ...string) func(*input) ([]step, string) {
	return func(in *input) ([]step, string) {
		in.state("started", "started")
		var ports, volumes []string
		for _, k := range keys {
			switch k {
			case "published_ports", "publish", "ports":
				ports = append(ports, in.list(k)...)
			default:
				volumes = append(volumes, in.list(k)...)
			}
		}
		c := container.Container{Engine: engine, Name: in.str("name"), Image: in.str("image"), Ports: ports, Volumes: volumes, Restart: in.str("restart_policy")}
		if n, ok := in.args["command"]; ok {
			if n.Kind == yaml.ScalarNode && strings.ContainsAny(n.Value, "'\"\\$`") {
				in.used["command"] = true
				return nil, "sets command as one string with quotes or shell characters, which Ansible splits as a shell would; write it as a list"
			}
			if n.Kind == yaml.ScalarNode {
				c.Command = strings.Fields(in.str("command"))
			} else {
				c.Command = in.list("command")
			}
		}
		if n, ok := in.args["env"]; ok {
			in.used["env"] = true
			c.Env = map[string]string{}
			for k, v := range mapping(n) {
				if v.Kind != yaml.ScalarNode {
					return nil, "sets env " + k + " to something other than one value"
				}
				c.Env[k] = in.render("env", v.Value)
			}
		}
		if err := c.Validate(); err != nil {
			return nil, err.Error()
		}
		attrs := []attr{s("name", c.Name), s("image", c.Image), s("engine", engine)}
		strs := func(key string, vs []string) {
			if len(vs) == 0 {
				return
			}
			vals := make([]cty.Value, len(vs))
			for i, v := range vs {
				vals[i] = cty.StringVal(v)
			}
			attrs = append(attrs, attr{key: key, val: cty.ListVal(vals)})
		}
		strs("ports", c.Ports)
		strs("volumes", c.Volumes)
		strs("command", c.Command)
		if len(c.Env) > 0 {
			vals := map[string]cty.Value{}
			for k, v := range c.Env {
				vals[k] = cty.StringVal(v)
			}
			attrs = append(attrs, attr{key: "env", val: cty.MapVal(vals)})
		}
		if c.Restart != "" {
			attrs = append(attrs, s("restart", c.Restart))
		}
		return one("container", attrs)
	}
}

// commandLine is a command or shell task's command as /bin/sh runs it, in
// its chdir, or why the converter can't read it as one.
func commandLine(in *input) (string, string) {
	if in.has("argv") {
		return commandArgvLine(in)
	}
	cmd := in.str("cmd")
	if n, ok := in.args["_raw"]; ok {
		for _, f := range strings.Fields(n.Value) {
			if k, _, ok := strings.Cut(f, "="); ok && inlineArgs[k] {
				return "", "sets " + k + " inside the command line; move it under args so the converter can read it"
			}
		}
		cmd = in.render("command", n.Value)
	}
	if cmd == "" {
		return "", "has no command"
	}
	if in.mod == "command" && shellSyntax.MatchString(cmd) {
		return "", "uses characters a shell reads, such as ; | $ * or >, which Ansible's command module hands to the program as plain text and a command step would run through /bin/sh; write it as you mean the shell to read it, in a command step"
	}
	if in.has("chdir") {
		cmd = "cd " + shellQuote(in.str("chdir")) + " && " + cmd
	}
	// Ansible's shell runs the command with executable -c; a command step
	// runs /bin/sh, dash on Debian, so another shell is asked for by name.
	// The command module ignores executable, as Ansible does.
	if exe := in.str("executable"); in.mod == "shell" && exe != "" && exe != "/bin/sh" && exe != "sh" {
		cmd = shellQuote(exe) + " -c " + shellQuote(cmd)
	}
	in.ignore("executable")
	return cmd, ""
}

// commandArgvLine is a command task's argv as /bin/sh runs it: one argument
// each, quoted so the shell hands the program the words Ansible did, with no
// quoting to read.
func commandArgvLine(in *input) (string, string) {
	if in.has("cmd") || in.has("_raw") {
		return "", "sets argv beside cmd, which Ansible refuses; keep one of them"
	}
	in.used["argv"] = true
	n := in.args["argv"]
	if n.Kind != yaml.SequenceNode {
		return "", "has an argv that isn't a list of arguments; write one argument on each line"
	}
	if len(n.Content) == 0 {
		return "", "has an empty argv, which runs no program"
	}
	// Ansible's command module passes each argument through expanduser and
	// expandvars before running it, unless expand_argument_vars is false, so a
	// quoted word here would hand the program the text instead of the value.
	// The shell module joins a list with shlex.quote and expands nothing.
	expand := in.mod != "command" || in.bool("expand_argument_vars", true)
	words := make([]string, 0, len(n.Content))
	for _, e := range n.Content {
		if e.Kind != yaml.ScalarNode {
			return "", "has an argument in argv that isn't a single value"
		}
		w := in.render("argv", e.Value)
		if expand && expandsInArgv(w) {
			return "", "has " + w + " in argv, which Ansible expands before running and a quoted argument wouldn't; write it in a shell step or set expand_argument_vars: false"
		}
		words = append(words, shellQuote(w))
	}
	line := strings.Join(words, " ")
	if in.has("chdir") {
		line = "cd " + shellQuote(in.str("chdir")) + " && " + line
	}
	in.ignore("executable")
	return line, ""
}

// argVar matches what os.path.expandvars replaces in Ansible's argv: $NAME
// and ${NAME}. A $ that starts neither is left as it is, so a quoted argument
// and Ansible agree on it.
var argVar = regexp.MustCompile(`\$[A-Za-z_{]`)

// expandsInArgv reports whether Ansible's command module would change an
// argument before running it.
func expandsInArgv(s string) bool {
	return strings.HasPrefix(s, "~") || argVar.MatchString(s)
}

func commandModule(in *input) ([]step, string) {
	cmd, why := commandLine(in)
	if why != "" {
		return nil, why
	}
	attrs := []attr{s("command", cmd)}
	attrs = in.optional(attrs, "creates", "creates")
	attrs = in.optional(attrs, "removes", "removes")
	for _, k := range []string{"creates", "removes"} {
		if strings.ContainsAny(in.str(k), "*?[") {
			return nil, k + " is a glob pattern; Conn3x tests the path as written"
		}
	}
	if !in.has("creates") && !in.has("removes") {
		return nil, "runs on every play; give it a creates, removes or unless guard, or triggers, so Conn3x knows when it's done"
	}
	// Ansible adds a newline to stdin unless stdin_add_newline is false.
	// stdin_wo keeps it out of state, and stdin_hmac plans a change when it
	// changes.
	if in.has("stdin") {
		text := in.str("stdin")
		if in.bool("stdin_add_newline", true) {
			text += "\n"
		}
		if text == "" {
			return nil, "sets an empty stdin with stdin_add_newline: no, so the command reads nothing; leave stdin out"
		}
		attrs = append(attrs, s("stdin_wo", text))
	}
	in.ignore("stdin_add_newline")
	if in.env != nil {
		env := map[string]cty.Value{}
		for i := 0; i+1 < len(in.env.Content); i += 2 {
			k, v := in.env.Content[i].Value, in.env.Content[i+1]
			if v.Kind != yaml.ScalarNode {
				return nil, "sets environment " + k + " to something that isn't a string"
			}
			env[k] = cty.StringVal(in.render("environment", v.Value))
		}
		if len(env) > 0 {
			attrs = append(attrs, attr{key: "environment", val: cty.MapVal(env)})
		}
	}
	return one("command", attrs)
}

func rebootModule(in *input) ([]step, string) {
	in.ignore("reboot_timeout", "msg")
	return nil, "reboots on every play; a Conn3x reboot step reboots once, and again when its triggers change, so add triggers"
}

func waitForModule(in *input) ([]step, string) {
	if h := in.str("host"); h != "" && h != "localhost" && h != "127.0.0.1" {
		return nil, "waits for another host, which the converter can't translate yet"
	}
	st := in.str("state")
	if st == "drained" {
		return nil, "waits for a port's open connections to finish, which wait_for can't do yet"
	}
	in.state("started", "started", "present", "stopped", "absent")
	var attrs []attr
	attrs = in.optional(attrs, "path", "path")
	if st == "stopped" || st == "absent" {
		attrs = append(attrs, s("state", "absent"))
	}
	// search_regex on a socket reads a banner, which wait_for can't yet.
	if in.has("search_regex") {
		if !in.has("path") {
			return nil, "sets search_regex on a port, which reads what the socket sends; the converter can't translate that yet"
		}
		pattern := in.text("search_regex")
		if in.problem != "" {
			return nil, in.problem
		}
		if why := unprovableRegexp(pattern); why != "" {
			return nil, why
		}
		attrs = append(attrs, s("contains", pattern))
	}
	if in.has("port") {
		attrs = append(attrs, in.number("port"))
	}
	if in.has("timeout") {
		secs, err := strconv.Atoi(in.str("timeout"))
		if err != nil {
			return nil, "has a timeout that isn't a number of seconds"
		}
		attrs = append(attrs, s("timeout", fmt.Sprintf("%ds", secs)))
	}
	in.ignore("delay")
	return one("wait_for", attrs)
}

// uriWait is a uri task's until, retries and delay: the codes it waits for,
// nil when it waits for the task to succeed, and how long in all.
type uriWait struct {
	codes   []string
	seconds int
}

var (
	untilStatus = regexp.MustCompile(`^(\w+)\.status\s*(?:==\s*(\d{3})|in\s*\[\s*(\d{3}(?:\s*,\s*\d{3})*)\s*\])$`)
	untilOK     = regexp.MustCompile(`^(\w+)\s+is\s+(?:succeeded|success|successful|not\s+failed)$`)
)

// uriRetry reads a uri task that polls a URL: until on the registered
// result's status, with retries and delay given as numbers.
func uriRetry(t map[string]*yaml.Node) *uriWait {
	if mod, _ := moduleOf(t); mod != "uri" || t["until"] == nil || t["until"].Kind != yaml.ScalarNode {
		return nil
	}
	reg, until := scalar(t["register"]), strings.TrimSpace(scalar(t["until"]))
	retries, err1 := strconv.Atoi(scalar(t["retries"]))
	delay, err2 := strconv.Atoi(scalar(t["delay"]))
	// With delay 0, Ansible retries back to back, and how long that takes
	// depends on each request, so retries * delay says nothing: a "0s"
	// wait_for would ask once. It stays for review.
	if reg == "" || err1 != nil || err2 != nil || retries < 1 || delay < 1 {
		return nil
	}
	w := &uriWait{seconds: retries * delay}
	if m := untilStatus.FindStringSubmatch(until); m != nil && m[1] == reg {
		for _, c := range strings.Split(m[2]+m[3], ",") {
			w.codes = append(w.codes, strings.TrimSpace(c))
		}
		return w
	}
	if m := untilOK.FindStringSubmatch(until); m != nil && m[1] == reg {
		return w
	}
	return nil
}

// uriModule converts a uri task that waits for a URL into wait_for.
func uriModule(in *input) ([]step, string) {
	if in.wait == nil {
		return nil, "makes a request; only a uri task that retries until a status answers converts yet, to wait_for"
	}
	if m := in.str("method"); m != "" && !strings.EqualFold(m, "GET") {
		return nil, "waits with a " + m + " request, and wait_for sends GET"
	}
	attrs := []attr{s("url", in.str("url"))}
	codes := in.wait.codes
	if c := in.list("status_code"); codes == nil {
		codes = c
	}
	if len(codes) > 0 && !slices.Equal(codes, []string{"200"}) {
		vals := make([]cty.Value, len(codes))
		for i, c := range codes {
			n, err := strconv.Atoi(c)
			if err != nil {
				return nil, "has a status_code that isn't a number"
			}
			vals[i] = cty.NumberIntVal(int64(n))
		}
		attrs = append(attrs, attr{key: "status_codes", val: cty.ListVal(vals)})
	}
	if in.has("validate_certs") && !truthy(in.str("validate_certs")) {
		attrs = append(attrs, attr{key: "skip_tls_verify", val: cty.True})
	}
	// timeout is per request; wait_for's covers the whole wait.
	in.ignore("timeout", "return_content")
	attrs = append(attrs, s("timeout", fmt.Sprintf("%ds", in.wait.seconds)))
	return one("wait_for", attrs, "Was a uri task retried until it answered; the registered result isn't kept.")
}

// aptLine is a one-line apt source: deb, optional [options], URL, suite and
// any components. Anything else, such as deb-src or a ppa: name, doesn't match.
var aptLine = regexp.MustCompile(`^deb(?:\s+\[([^\]]*)\])?\s+(\S+)\s+(\S+)((?:\s+\S+)*)$`)

var keyFileName = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9_.+-]*$`)

// repoKey finds the armored key a playbook names by URL or host path. Conn3x
// needs the key itself, and the converter doesn't download anything, so it has
// to be beside the playbook under the same file name.
func (in *input) repoKey(from string) (key, file, reason string) {
	u, err := url.Parse(from)
	if err != nil {
		return "", "", fmt.Sprintf("names the signing key %q, which the converter can't read as a path or URL", from)
	}
	base := path.Base(u.Path)
	if !keyFileName.MatchString(base) {
		return "", "", fmt.Sprintf("names the signing key %q, which has no usable file name", from)
	}
	file = in.local("files", base)
	if file == "" {
		return "", "", fmt.Sprintf("needs the signing key itself, which Conn3x stores on the host; save %s as files/%s beside the playbook and convert again", from, base)
	}
	data, err := os.ReadFile(filepath.Join(in.dir, file))
	if err != nil {
		return "", "", fmt.Sprintf("can't read the signing key %s: %v", file, err)
	}
	return string(data), file, ""
}

func stringList(ss []string) cty.Value {
	vals := make([]cty.Value, len(ss))
	for i, v := range ss {
		vals[i] = cty.StringVal(v)
	}
	return cty.ListVal(vals)
}

func aptRepositoryModule(in *input) ([]step, string) {
	if in.loop {
		return nil, "loops over repository lines, which the converter can't translate yet; write one task for each"
	}
	in.state("present", "present")
	line := strings.TrimSpace(in.str("repo"))
	if in.problem != "" {
		return nil, in.problem
	}
	m := aptLine.FindStringSubmatch(line)
	if m == nil {
		return nil, fmt.Sprintf("has the repo %q, which isn't a one-line deb source with a URL and suite; deb-src and ppa: stay for a person", line)
	}
	if !in.bool("update_cache", true) || !in.bool("update-cache", true) {
		return nil, "sets update_cache: no; Conn3x always runs apt-get update after writing a repository"
	}
	in.ignore("install_python_apt") // only what Ansible itself needs on the host
	signedBy := ""
	for _, opt := range strings.Fields(m[1]) {
		v, ok := strings.CutPrefix(opt, "signed-by=")
		if !ok {
			return nil, fmt.Sprintf("sets the apt option %q, which a repository step doesn't have", opt)
		}
		signedBy = v
	}
	if !strings.HasPrefix(signedBy, "/") {
		return nil, "doesn't name a key file with signed-by=/path; a repository step trusts one key for this repository only, and the converter can't tell which"
	}
	source, suite, components := m[2], m[3], strings.Fields(m[4])
	flat := strings.HasSuffix(suite, "/")
	if flat != (len(components) == 0) {
		return nil, fmt.Sprintf("has the suite %q with %d components; apt wants components unless the suite ends in /", suite, len(components))
	}
	u, err := url.Parse(source)
	if err != nil {
		return nil, fmt.Sprintf("has the URL %q, which the converter can't read", source)
	}
	key, keyFile, reason := in.repoKey(signedBy)
	if reason != "" {
		return nil, reason
	}
	// The suite and components are in the name so that two sources from one URL get a file each.
	name := slug(strings.Join(append([]string{u.Host + u.Path, suite}, components...), " "))
	if err := (repo.Repo{Name: name, URL: source, Key: key, Suites: []string{suite}, Components: components}).Validate(pkg.Deb); err != nil {
		return nil, "can't be a repository step: " + err.Error()
	}
	attrs := []attr{s("name", name), s("url", source), {key: "key", raw: "file(" + moduleFile(keyFile) + ")"}, {key: "suites", val: stringList([]string{suite})}}
	if len(components) > 0 {
		attrs = append(attrs, attr{key: "components", val: stringList(components)})
	}
	return one("repository", attrs,
		fmt.Sprintf("Check that %s is the key %s holds on the host.", keyFile, signedBy),
		"TODO(convert): Delete the .list file Ansible left in /etc/apt/sources.list.d for this repository, or apt sees it twice.")
}

func yumRepositoryModule(in *input) ([]step, string) {
	if in.loop {
		return nil, "loops over repositories, which the converter can't translate yet; write one task for each"
	}
	in.state("present", "present")
	name := in.str("name")
	if in.problem != "" {
		return nil, in.problem
	}
	urls := in.list("baseurl")
	if len(urls) != 1 {
		return nil, "doesn't set exactly one baseurl; a repository step has one URL, and no metalink or mirrorlist"
	}
	if !in.bool("enabled", true) {
		return nil, "sets enabled: no; Conn3x always enables the repository"
	}
	if !in.bool("gpgcheck", false) {
		return nil, "doesn't set gpgcheck: yes; Conn3x always checks signatures, which Ansible leaves to the host's own setting"
	}
	if in.has("file") && in.str("file") != name {
		return nil, "sets file to something other than name; Conn3x names the .repo file after the repository"
	}
	keys := in.list("gpgkey")
	if len(keys) != 1 {
		return nil, "doesn't set exactly one gpgkey; a repository step has one key"
	}
	key, keyFile, reason := in.repoKey(keys[0])
	if reason != "" {
		return nil, reason
	}
	if err := (repo.Repo{Name: name, URL: urls[0], Key: key}).Validate(pkg.RPM); err != nil {
		return nil, "can't be a repository step: " + err.Error()
	}
	notes := []string{fmt.Sprintf("Check that %s is the key at %s.", keyFile, keys[0])}
	if in.has("description") {
		in.ignore("description")
		notes = append(notes, "description dropped: Conn3x labels the repository with its name.")
	}
	return one("repository", []attr{s("name", name), s("url", urls[0]), {key: "key", raw: "file(" + moduleFile(keyFile) + ")"}}, notes...)
}

// A locale step also sets the host's LANG, which locale_gen doesn't, so
// converting one would change something the playbook never asked for.
func localeGenModule(*input) ([]step, string) {
	return nil, "only generates a locale, and a locale step also sets the host's LANG; use a guarded command step, or a locale step if you do want it as the system locale"
}

// inlineArgs are the options Ansible pulls out of a free-form command line.
var inlineArgs = map[string]bool{"chdir": true, "creates": true, "removes": true, "executable": true, "stdin": true, "stdin_add_newline": true, "strip_empty_ends": true, "warn": true}

func shellQuote(v string) string { return "'" + strings.ReplaceAll(v, "'", `'\''`) + "'" }

// joinAnd lists names as "a", "a and b" or "a, b and c", and past three
// as "5 files under vars/, such as a and b".
func joinAnd(names []string) string {
	if len(names) > 3 {
		return fmt.Sprintf("%d files under vars/, such as %s and %s", len(names), names[0], names[1])
	}
	if len(names) < 2 {
		return strings.Join(names, "")
	}
	return strings.Join(names[:len(names)-1], ", ") + " and " + names[len(names)-1]
}
