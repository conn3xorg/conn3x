// Copyright (c) The Conn3x Authors
// SPDX-License-Identifier: MPL-2.0

package ansible

import (
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/hashicorp/hcl/v2/hclparse"
	"gopkg.in/yaml.v3"
)

// goldenRole converts testdata/role/<name> and compares every file with
// testdata/role/<name>.circuit.
func goldenRole(t *testing.T, name string) Result {
	t.Helper()
	res, err := ConvertRole(filepath.Join("testdata", "role", name))
	if err != nil {
		t.Fatal(err)
	}
	dir := filepath.Join("testdata", "role", name+".circuit")
	if *update {
		os.RemoveAll(dir)
		for p, b := range res.Files {
			if err := os.MkdirAll(filepath.Join(dir, filepath.Dir(p)), 0o755); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(filepath.Join(dir, p), b, 0o644); err != nil {
				t.Fatal(err)
			}
		}
	}
	want := map[string]bool{}
	_ = filepath.WalkDir(dir, func(p string, d fs.DirEntry, err error) error {
		if err == nil && !d.IsDir() {
			rel, _ := filepath.Rel(dir, p)
			want[filepath.ToSlash(rel)] = true
		}
		return err
	})
	for p, b := range res.Files {
		golden, err := os.ReadFile(filepath.Join(dir, p))
		if err != nil {
			t.Errorf("%s is new (run with -update to accept):\n%s", p, b)
			continue
		}
		delete(want, p)
		if string(golden) != string(b) {
			t.Errorf("%s differs from %s (run with -update to accept):\n%s", p, dir, b)
		}
		if strings.HasSuffix(p, ".hcl") || strings.HasSuffix(p, ".tf") {
			if _, diags := hclparse.NewParser().ParseHCL(b, p); diags.HasErrors() {
				t.Errorf("%s is not valid HCL: %s", p, diags)
			}
		}
	}
	for p := range want {
		t.Errorf("%s is no longer written", p)
	}
	return res
}

func TestConvertRoleGolden(t *testing.T) {
	res := goldenRole(t, "app")
	if res.Converted != 7 || len(res.Review) != 0 {
		t.Fatalf("converted %d, review %+v", res.Converted, res.Review)
	}
}

func TestConvertRoleRefuses(t *testing.T) {
	res := goldenRole(t, "mixed")
	for _, want := range []string{
		"runs the roles common, geerlingguy.firewall first",
		"checks the role's arguments",
		"includes a file per family, and for Debian hosts it imports Debian.yml, which wasn't found",
		"imports nowhere.yml, which wasn't found",
		"which is already being imported",
		"uses include_role",
		"sets become, which in a circuit the ssh block decides",
		`mode refers to the role default "mixed_mode"`,
		"uses Jinja statements",
		"is outside the role's files/",
	} {
		found := false
		for _, r := range res.Review {
			found = found || strings.Contains(r.Reason, want)
		}
		if !found {
			t.Errorf("no review item says %q: %+v", want, res.Review)
		}
	}
	// The import behind a family when converts, as each task given it, and
	// so does the path from a default.
	if res.Converted != 2 || len(res.Review) != 10 {
		t.Errorf("converted %d, review %d", res.Converted, len(res.Review))
	}
}

func TestRolePlainValues(t *testing.T) {
	src := `
s: hello
q: "yes"
p: /opt/app
i: 8080
neg: -1
oct: 0777
f: 1.5
b: yes
B: True
null1: ~
empty:
date: 2026-11-07
list: [a]
txt: "[a, b]"
jinja: "{{ x }}"
lit: |
  two
  lines
`
	want := map[string]string{"s": "hello", "q": "yes", "p": "/opt/app", "i": "8080#", "neg": "-1#", "lit": "two\nlines\n"}
	var doc yaml.Node
	if err := yaml.Unmarshal([]byte(src), &doc); err != nil {
		t.Fatal(err)
	}
	for _, kv := range pairs(doc.Content[0]) {
		v, num, why := plainValue(kv[1])
		got := v
		if num {
			got += "#"
		}
		if why != "" {
			got = ""
		}
		if got != want[kv[0].Value] {
			t.Errorf("%s: got %q (%s), want %q", kv[0].Value, got, why, want[kv[0].Value])
		}
	}
}

func TestConvertRoleNeedsTasks(t *testing.T) {
	if _, err := ConvertRole(t.TempDir()); err == nil || !strings.Contains(err.Error(), "no tasks/ directory") {
		t.Fatalf("got %v", err)
	}
}

// A playbook's import_tasks inlines too, from beside the playbook.
func TestPlaybookImportTasks(t *testing.T) {
	dir := t.TempDir()
	for name, src := range map[string]string{
		"more.yml": "- name: Tools\n  package: {name: jq}\n",
		"play.yml": "- hosts: all\n  tasks:\n    - import_tasks: more.yml\n",
	} {
		if err := os.WriteFile(filepath.Join(dir, name), []byte(src), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	res, err := Convert(filepath.Join(dir, "play.yml"))
	if err != nil {
		t.Fatal(err)
	}
	if res.Converted != 1 || len(res.Review) != 0 || !strings.Contains(string(res.HCL), `name = "jq"`) {
		t.Fatalf("converted %d, review %+v\n%s", res.Converted, res.Review, res.HCL)
	}
}

// A variable set per OS under vars/ says where it comes from, until the
// converter can translate the include_vars that loads it.
func TestRoleVariableFromAnIncludeVarsFile(t *testing.T) {
	dir := writeRole(t, map[string]string{
		"vars/Debian.yml": "nginx_user: www-data\n",
		"vars/RedHat.yml": "nginx_user: nginx\n",
		"vars/main.yml":   "unrelated: x\n",
		"tasks/main.yml":  "- name: Owner\n  file: {path: /srv/www, state: directory, owner: '{{ nginx_user }}'}\n- name: Other\n  file: {path: /srv/x, state: directory, owner: '{{ nope }}'}\n",
	})
	res, err := ConvertRole(dir)
	if err != nil {
		t.Fatal(err)
	}
	if len(res.Review) != 2 {
		t.Fatalf("review %+v", res.Review)
	}
	want := `refers to "nginx_user", which is set in vars/Debian.yml and vars/RedHat.yml, loaded by an include_vars`
	if !strings.Contains(res.Review[0].Reason, want) {
		t.Errorf("reason = %q, want it to contain %q", res.Review[0].Reason, want)
	}
	if !strings.Contains(res.Review[1].Reason, `which isn't a role variable the converter can fill in`) {
		t.Errorf("a variable from nowhere kept the old reason: %q", res.Review[1].Reason)
	}
}

// A handler's service name fills in play vars, and anything but a service
// restart or reload, or a when, stays for review.
func TestHandlerNameFromAVarAndKeywords(t *testing.T) {
	res := convertString(t, `- hosts: all
  vars: {svc: nginx}
  tasks:
    - copy: {dest: /etc/a, content: x}
      notify: [Restart, Maybe]
  handlers:
    - name: Restart
      service: {name: "{{ svc }}", state: restarted}
    - name: Maybe
      service: {name: nginx, state: reloaded}
      when: false
`)
	if !strings.Contains(string(res.HCL), `name   = "nginx"`) || len(res.Review) != 2 || !strings.Contains(res.Review[0].Reason, "with a when") {
		t.Fatalf("review %+v\n%s", res.Review, res.HCL)
	}
}

// A role that loads vars/<family>.yml becomes steps whose values are looked
// up by each host's family, read from conn3x_host.
func TestRoleFamilyVars(t *testing.T) {
	res := goldenRole(t, "cron")
	if res.Converted != 4 || len(res.Review) != 0 {
		t.Fatalf("converted %d, review %+v", res.Converted, res.Review)
	}
	if v := string(res.Files["variables.tf"]); !strings.Contains(v, "CentOS Linux reached end of life") || strings.Contains(string(res.Files["main.circuit.hcl"]), "centos") {
		t.Errorf("hosts should refuse centos as an os, as the official circuits do:\n%s", v)
	}
}

// set_fact: X: "{{ __X }}" when X is not defined becomes a variable the
// caller can set, with the family's value when it's null.
func TestRoleFamilyDefaults(t *testing.T) {
	res := goldenRole(t, "svc")
	if res.Converted != 3 || len(res.Review) != 0 {
		t.Fatalf("converted %d, review %+v", res.Converted, res.Review)
	}
	hcl := string(res.Files["main.circuit.hcl"])
	if !strings.Contains(hcl, `owner = var.svc_user != null ? var.svc_user : { debian = "www-data", redhat = "nobody" }[local.os_family[each.key]]`) {
		t.Errorf("owner isn't the caller's value or the family's:\n%s", hcl)
	}
	if v := string(res.Files["variables.tf"]); !strings.Contains(v, `variable "svc_user"`) || !strings.Contains(v, "default     = null") {
		t.Errorf("no svc_user variable:\n%s", v)
	}
}

// A when on the family becomes the step's when, and the task converts
// only for the families it allows: famwhen_rh_dir is only in RedHat.yml.
func TestRoleFamilyWhen(t *testing.T) {
	res, err := ConvertRole(filepath.Join("testdata", "role", "famwhen"))
	if err != nil {
		t.Fatal(err)
	}
	// The last task's != names a family Conn3x doesn't run on, which is
	// always true on a Conn3x host: no when.
	if res.Converted != 4 || len(res.Review) != 0 {
		t.Fatalf("converted %d, review %+v", res.Converted, res.Review)
	}
	goldenRole(t, "famwhen")
	hcl := string(res.Files["main.circuit.hcl"])
	for _, want := range []string{
		`when = local.os_family[each.key] == "debian"`,
		`when = local.os_family[each.key] == "redhat"`,
		`path    = "/etc/famwhen-all"`,
		`path = "/srv/famwhen-redhat"`,
	} {
		if !strings.Contains(hcl, want) {
			t.Errorf("missing %s in\n%s", want, hcl)
		}
	}
}

// An in list with a family Conn3x doesn't run on means just the others.
func TestRoleFamilyWhenUnknownFamilyInList(t *testing.T) {
	res, err := ConvertRole(writeRole(t, map[string]string{
		"tasks/main.yml":  "- name: Vars\n  include_vars: \"{{ ansible_os_family }}.yml\"\n- name: T\n  copy: {dest: /etc/t, content: x}\n  when: ansible_os_family in ['Debian', 'Archlinux']\n",
		"vars/Debian.yml": "a: x\n", "vars/RedHat.yml": "a: y\n",
	}))
	if err != nil {
		t.Fatal(err)
	}
	if len(res.Review) != 0 || !strings.Contains(string(res.Files["main.circuit.hcl"]), `when = local.os_family[each.key] == "debian"`) {
		t.Fatalf("review %+v\n%s", res.Review, res.Files["main.circuit.hcl"])
	}
}

// include_tasks by family inlines each family's tasks with that family as
// their when: by a file named by the family, or a fixed file whose include
// has a when on the family. An include only for a family Conn3x doesn't run
// on is one review item.
func TestRoleFamilyInclude(t *testing.T) {
	res, err := ConvertRole(filepath.Join("testdata", "role", "famincl"))
	if err != nil {
		t.Fatal(err)
	}
	if res.Converted != 3 || len(res.Review) != 1 || !strings.Contains(res.Review[0].Reason, "includes setup-Archlinux.yml with a when no Debian or Red Hat family host meets") {
		t.Fatalf("converted %d, review %+v", res.Converted, res.Review)
	}
	goldenRole(t, "famincl")
	hcl := string(res.Files["main.circuit.hcl"])
	for _, want := range []string{
		"step \"debian_setup\" {\n    when = local.os_family[each.key] == \"debian\"",
		"step \"red_hat_setup\" {\n    when = local.os_family[each.key] == \"redhat\"",
		"step \"debian_extra\" {\n    when = local.os_family[each.key] == \"debian\"",
	} {
		if !strings.Contains(hcl, want) {
			t.Errorf("missing %q in\n%s", want, hcl)
		}
	}
	// A family's file that's missing goes to review, naming it.
	res, err = ConvertRole(writeRole(t, map[string]string{
		"tasks/main.yml":         "- name: Setup\n  include_tasks: \"setup-{{ ansible_os_family }}.yml\"\n",
		"tasks/setup-Debian.yml": "- name: D\n  copy: {dest: /etc/d, content: x}\n",
	}))
	if err != nil {
		t.Fatal(err)
	}
	if len(res.Review) != 1 || !strings.Contains(res.Review[0].Reason, "for RedHat hosts it imports setup-RedHat.yml, which wasn't found") {
		t.Fatalf("review %+v", res.Review)
	}
}

func TestRoleFamilyWhenRefusals(t *testing.T) {
	include := "- name: Vars\n  include_vars: \"{{ ansible_os_family }}.yml\"\n"
	vars := map[string]string{"vars/Debian.yml": "a: x\n", "vars/RedHat.yml": "a: y\n"}
	for want, task := range map[string]string{
		"no Debian or Red Hat family host meets": "  when: ansible_os_family == 'Archlinux'\n",
		"would never run":                        "  when: [ansible_os_family == 'Debian', ansible_os_family == 'RedHat']\n",
		"uses when":                              "  when: ansible_os_family == 'Debian' and x\n",
	} {
		files := map[string]string{"tasks/main.yml": include + "- name: T\n  copy: {dest: /etc/t, content: x}\n" + task}
		for k, v := range vars {
			files[k] = v
		}
		res, err := ConvertRole(writeRole(t, files))
		if err != nil {
			t.Fatal(err)
		}
		if len(res.Review) != 1 || !strings.Contains(res.Review[0].Reason, want) {
			t.Errorf("%s: review %+v", want, res.Review)
		}
	}
}

func TestRoleFamilyVarsRefusals(t *testing.T) {
	include := "- name: Vars\n  include_vars: \"{{ ansible_os_family }}.yml\"\n"
	for want, files := range map[string]map[string]string{
		// A family whose file doesn't set the variable.
		`which vars/RedHat.yml doesn't set, so Ansible would stop on RedHat hosts`: {
			"tasks/main.yml":  include + "- name: P\n  package: {name: '{{ pkg }}'}\n",
			"vars/Debian.yml": "pkg: cron\n",
			"vars/RedHat.yml": "other: x\n",
		},
		// A value one family's checks refuse.
		"(with the values for RedHat hosts)": {
			"tasks/main.yml":  include + "- name: C\n  copy: {dest: /etc/a.conf, content: x, mode: '{{ m }}'}\n",
			"vars/Debian.yml": "m: \"0644\"\n",
			"vars/RedHat.yml": "m: u+rw\n",
		},
		// Set, but to something the converter can't use.
		"which vars/RedHat.yml sets to a list, a map or an alias, which the converter can't use yet": {
			"tasks/main.yml":  include + "- name: P\n  package: {name: '{{ pkg }}'}\n",
			"vars/Debian.yml": "pkg: cron\n",
			"vars/RedHat.yml": "pkg: [cronie, cronie-anacron]\n",
		},
		// A caller's value where Conn3x would have to check it first.
		`dest refers to "conf", which the caller can set`: {
			"tasks/main.yml":  include + "- name: D\n  set_fact: {conf: '{{ __conf }}'}\n  when: conf is not defined\n- name: C\n  copy: {dest: '{{ conf }}', content: x}\n",
			"vars/Debian.yml": "__conf: /etc/a.conf\n",
			"vars/RedHat.yml": "__conf: /etc/b.conf\n",
		},
		// No RedHat file: the include isn't the family pattern Conn3x reads.
		"uses the include_vars module": {
			"tasks/main.yml":  include,
			"vars/Debian.yml": "pkg: cron\n",
		},
	} {
		res, err := ConvertRole(writeRole(t, files))
		if err != nil {
			t.Fatal(err)
		}
		found := false
		for _, r := range res.Review {
			found = found || strings.Contains(r.Reason, want)
		}
		if !found {
			t.Errorf("%s: review %+v", want, res.Review)
		}
	}
}

// writeRole writes a role's files into a new directory.
func writeRole(t *testing.T, files map[string]string) string {
	t.Helper()
	dir := t.TempDir()
	for name, src := range files {
		p := filepath.Join(dir, filepath.FromSlash(name))
		if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(p, []byte(src), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	return dir
}

// A true-or-false default becomes a bool variable, and a when that switches
// on it becomes the step's when. Printing one stays for review: Ansible
// writes True, HCL true.
func TestRoleBoolDefaultSwitch(t *testing.T) {
	res, err := ConvertRole(writeRole(t, map[string]string{
		"defaults/main.yml": "web_enabled: yes\nweb_extra: false\n",
		"tasks/main.yml": `- name: Install web
  package: { name: nginx }
  when: web_enabled | bool
- name: Remove extra
  file: { path: /etc/extra, state: absent }
  when: not (web_extra | bool)
- name: Keep extra
  file: { path: /etc/keep, state: directory }
  when: web_extra
- name: Print it
  copy: { dest: /etc/flag, content: "{{ web_enabled }}" }
`,
	}))
	if err != nil {
		t.Fatal(err)
	}
	hcl, vars := string(res.Files["main.circuit.hcl"]), string(res.Files["variables.tf"])
	for _, w := range []string{"when = var.web_enabled", "when = !var.web_extra", "when = var.web_extra"} {
		if !strings.Contains(hcl, w) {
			t.Errorf("missing %q:\n%s", w, hcl)
		}
	}
	if !strings.Contains(vars, "type        = bool\n  default     = true") || !strings.Contains(vars, "default     = false") {
		t.Errorf("bool variables:\n%s", vars)
	}
	if res.Converted != 3 || len(res.Review) != 1 || !strings.Contains(res.Review[0].Reason, "True or False") {
		t.Errorf("converted %d, review %+v", res.Converted, res.Review)
	}
}

// A loop over a role default that's a list of plain values becomes
// for_each over a list(string) variable. Anything else about the list, or
// a list used other than as a loop, stays for review.
func TestRoleLoopOverAListDefault(t *testing.T) {
	dir := writeRole(t, map[string]string{
		"defaults/main.yml": "admins: [alice, bob]\nnone_yet: []\nvhosts: [{name: a}]\ntwice: [a, a]\nunused: [x]\n",
		"tasks/main.yml": `- name: Admins
  user: {name: "{{ item }}"}
  with_items: "{{ admins }}"
- name: Nobody yet
  user: {name: "{{ item }}"}
  loop: "{{ none_yet }}"
- name: Vhosts
  file: {path: "/srv/{{ item.name }}", state: directory}
  with_items: "{{ vhosts }}"
- name: Twice
  user: {name: "{{ item }}"}
  loop: "{{ twice }}"
- name: As a value
  package: {name: "{{ admins }}"}
`,
	})
	res, err := ConvertRole(dir)
	if err != nil {
		t.Fatal(err)
	}
	main, vars := string(res.Files["main.circuit.hcl"]), string(res.Files["variables.tf"])
	for _, want := range []string{"for_each = var.admins", "for_each = var.none_yet"} {
		if !strings.Contains(main, want) {
			t.Errorf("main.circuit.hcl has no %q:\n%s", want, main)
		}
	}
	for _, want := range []string{`variable "admins" {`, `type        = list(string)`, `default     = ["alice", "bob"]`, `variable "none_yet" {`, `default     = []`, `Default "unused" (defaults/main.yml line 5) is a list`} {
		if !strings.Contains(vars, want) {
			t.Errorf("variables.tf has no %q:\n%s", want, vars)
		}
	}
	for _, gone := range []string{`variable "twice"`, `variable "unused"`} {
		if strings.Contains(vars, gone) {
			t.Errorf("variables.tf has %s:\n%s", gone, vars)
		}
	}
	var tasks []string
	for _, r := range res.Review {
		tasks = append(tasks, r.Task)
	}
	// A list of maps with a field in a path converts since #879.
	// A package task whose name is the list installs each item since it
	// reads as a loop over it.
	if strings.Join(tasks, ",") != "Twice" || !strings.Contains(vars, `variable "vhosts"`) {
		t.Errorf("review %+v", res.Review)
	}
}

// An include_tasks of one fixed file, with nothing on it but a name or
// tags, reads what an import would, so it's inlined. A when, a loop,
// a never tag or a file named by Jinja keeps it for review.
func TestStaticIncludeTasks(t *testing.T) {
	dir := writeRole(t, map[string]string{
		"tasks/configure.yml": "- name: Tools\n  package: {name: jq}\n",
		"tasks/main.yml": `- include_tasks: configure.yml
- name: Named, tagged, FQCN
  ansible.builtin.include_tasks:
    file: configure.yml
  tags: [config]
- include_tasks: configure.yml
  when: thing | bool
- include_tasks: configure.yml
  with_items: [a, b]
- include_tasks: configure.yml
  loop: [a, b]
- include_tasks: configure.yml
  tags: [never]
- include_tasks: "{{ which }}.yml"
`,
	})
	res, err := ConvertRole(dir)
	if err != nil {
		t.Fatal(err)
	}
	if res.Converted != 2 || strings.Count(string(res.Files["main.circuit.hcl"]), `name = "jq"`) != 2 {
		t.Errorf("converted %d\n%s", res.Converted, res.Files["main.circuit.hcl"])
	}
	if len(res.Review) != 5 {
		t.Errorf("review %d, want 5: %+v", len(res.Review), res.Review)
	}
}

// An import's when goes on every task it imports, as Ansible does. An
// include's goes on them only when it's a role's on-off switch, which no
// step can change between the include and its tasks.
func TestWhenOnImportsAndIncludes(t *testing.T) {
	dir := writeRole(t, map[string]string{
		"defaults/main.yml":  "ban_enabled: true\nport: 22\n",
		"tasks/fail2ban.yml": "- name: Fail2ban\n  package: {name: fail2ban}\n",
		"tasks/main.yml": `- import_tasks: fail2ban.yml
  when: ban_enabled | bool
- include_tasks: fail2ban.yml
  when: not ban_enabled
- include_tasks: fail2ban.yml
  when: port == 22
- import_tasks: fail2ban.yml
  when: port == 22
- include_tasks: fail2ban.yml
  when:
    - not ban_enabled
    - ansible_facts.os_family == 'Debian'
`,
	})
	res, err := ConvertRole(dir)
	if err != nil {
		t.Fatal(err)
	}
	main := string(res.Files["main.circuit.hcl"])
	for _, want := range []string{"when = var.ban_enabled", "when = !var.ban_enabled", `when = local.os_family[each.key] == "debian" && !var.ban_enabled`} {
		if !strings.Contains(main, want) {
			t.Errorf("no %q:\n%s", want, main)
		}
	}
	if res.Converted != 3 || len(res.Review) != 2 {
		t.Fatalf("converted %d, review %+v", res.Converted, res.Review)
	}
	// The include's when isn't a switch, so it stays whole; the import's
	// goes on its task, which then can't convert that when.
	if !strings.Contains(res.Review[0].Reason, "include_tasks") || res.Review[1].File != "tasks/fail2ban.yml" || !strings.Contains(res.Review[1].Reason, "uses when") {
		t.Errorf("review %+v", res.Review)
	}
}

// A when list ANDs its conditions: role switches and family tests convert
// together, and anything else in the list keeps the task for review.
func TestWhenListOfSwitchesAndFamily(t *testing.T) {
	dir := writeRole(t, map[string]string{
		"defaults/main.yml": "ban_enabled: true\nrepo_add: false\n",
		"tasks/main.yml": `- name: Both
  package: {name: fail2ban}
  when:
    - ban_enabled | bool
    - ansible_facts.os_family == 'Debian'
- name: Two switches
  package: {name: jq}
  when: [ban_enabled, not repo_add]
- name: And something else
  package: {name: git}
  when:
    - ban_enabled | bool
    - result.rc != 0
`,
	})
	res, err := ConvertRole(dir)
	if err != nil {
		t.Fatal(err)
	}
	main := string(res.Files["main.circuit.hcl"])
	for _, want := range []string{`when = local.os_family[each.key] == "debian" && var.ban_enabled`, `when = var.ban_enabled && !var.repo_add`} {
		if !strings.Contains(main, want) {
			t.Errorf("no %q:\n%s", want, main)
		}
	}
	if res.Converted != 2 || len(res.Review) != 1 || res.Review[0].Task != "And something else" {
		t.Errorf("converted %d, review %+v", res.Converted, res.Review)
	}
}

// A default that a file under vars/ also sets loses to it in Ansible once
// an include_vars loads that file, so it isn't a variable: tasks get the
// per-family value, or stay for review.
func TestDefaultShadowedByFamilyVars(t *testing.T) {
	dir := writeRole(t, map[string]string{
		"defaults/main.yml": "pkg: generic\nflag: true\nonly_deb: fallback\n",
		"vars/Debian.yml":   "pkg: deb-pkg\nflag: false\nonly_deb: deb-only\n",
		"vars/RedHat.yml":   "pkg: rh-pkg\nflag: false\n",
		"tasks/main.yml": `- name: Load OS vars
  include_vars: "{{ ansible_os_family }}.yml"
- name: Install
  package: {name: "{{ pkg }}"}
- name: Flagged
  package: {name: jq}
  when: flag | bool
- name: Debian only value
  package: {name: "{{ only_deb }}"}
`,
	})
	res, err := ConvertRole(dir)
	if err != nil {
		t.Fatal(err)
	}
	main, vars := string(res.Files["main.circuit.hcl"]), string(res.Files["variables.tf"])
	if strings.Contains(main, "var.pkg") || strings.Contains(main, "var.flag") || !strings.Contains(main, `"deb-pkg"`) || !strings.Contains(main, `"rh-pkg"`) {
		t.Errorf("main.circuit.hcl:\n%s", main)
	}
	if strings.Contains(vars, `variable "pkg"`) || !strings.Contains(vars, `Default "pkg" (defaults/main.yml line 1) is also set in vars/Debian.yml and vars/RedHat.yml`) {
		t.Errorf("variables.tf:\n%s", vars)
	}
	var got []string
	for _, r := range res.Review {
		got = append(got, r.Task+": "+r.Reason)
	}
	if len(got) != 2 || !strings.Contains(got[0], "Flagged") || !strings.Contains(got[1], "RedHat hosts get the role default") {
		t.Errorf("review:\n%s", strings.Join(got, "\n"))
	}
}

// with_items over a written list of plain values, or of maps, is loop over
// it; both loop and with_items stays for review.
func TestWithItemsLiteralList(t *testing.T) {
	res := convertString(t, `- hosts: all
  tasks:
    - name: Tools
      package: {name: "{{ item }}"}
      with_items: [git, jq]
    - name: Users
      user: {name: "{{ item.name }}"}
      with_items:
        - {name: a}
    - name: Both
      package: {name: "{{ item }}"}
      loop: [a]
      with_items: [b]
`)
	hcl := string(res.HCL)
	if !strings.Contains(hcl, `for_each = ["git", "jq"]`) || res.Converted != 2 || len(res.Review) != 1 {
		t.Errorf("converted %d, review %+v\n%s", res.Converted, res.Review, hcl)
	}
	if len(res.Review) == 1 && !strings.Contains(res.Review[0].Reason, "both loop and with_items") {
		t.Errorf("review %+v", res.Review)
	}
}

// A text default compared to text is a when that can't change in a run,
// so it converts, alone, in a list, or on an include. A number default
// compared to text stays: Jinja and HCL both say false, but it's a bug.
func TestWhenTextDefault(t *testing.T) {
	dir := writeRole(t, map[string]string{
		"defaults/main.yml": "method: package\nport: 80\n",
		"tasks/snap.yml":    "- name: Snap\n  package: {name: snapd}\n",
		"tasks/main.yml": `- name: From packages
  package: {name: docker-ce}
  when: method == 'package'
- name: Not on Debian from source
  package: {name: gcc}
  when:
    - method != "package"
    - ansible_facts.os_family == 'RedHat'
- include_tasks: snap.yml
  when: method == 'snap'
- name: Number
  package: {name: x}
  when: port == '80'
`,
	})
	res, err := ConvertRole(dir)
	if err != nil {
		t.Fatal(err)
	}
	main := strings.Join(strings.Fields(string(res.Files["main.circuit.hcl"])), " ")
	for _, want := range []string{`when = var.method == "package"`, `when = local.os_family[each.key] == "redhat" && var.method != "package"`, `when = var.method == "snap"`} {
		if !strings.Contains(main, want) {
			t.Errorf("no %q:\n%s", want, main)
		}
	}
	if res.Converted != 3 || len(res.Review) != 1 || res.Review[0].Task != "Number" {
		t.Errorf("converted %d, review %+v", res.Converted, res.Review)
	}
}

// item from a role's list default is held to what the default itself is:
// only where Conn3x uses the value exactly as Ansible does, and a package
// name without a comma.
func TestListDefaultItemIsHeldLikeADefault(t *testing.T) {
	dir := writeRole(t, map[string]string{
		"defaults/main.yml": "dirs: [/srv/a]\npkgs: [git, jq]\n",
		"tasks/main.yml": `- name: Dirs
  file: {path: "{{ item }}", state: directory}
  loop: "{{ dirs }}"
- name: Packages
  package: {name: "{{ item }}"}
  loop: "{{ pkgs }}"
`,
	})
	res, err := ConvertRole(dir)
	if err != nil {
		t.Fatal(err)
	}
	if res.Converted != 2 || len(res.Review) != 0 {
		t.Errorf("converted %d, review %+v", res.Converted, res.Review)
	}
	vars := string(res.Files["variables.tf"])
	for _, want := range []string{
		`alltrue([for p in var.pkgs : !strcontains(p, ",")])`,
		`alltrue([for p in var.dirs : startswith(p, "/")])`,
	} {
		if !strings.Contains(vars, want) {
			t.Errorf("missing %s in\n%s", want, vars)
		}
	}
}

// A role default or a loop item can go in a path when the path is
// absolute whatever the caller sets: a validation makes a default that
// starts the path start with /, and one that ends it not end in /.
func TestRoleDefaultsInPaths(t *testing.T) {
	res, err := ConvertRole(writeRole(t, map[string]string{
		"defaults/main.yml": "conf_dir: /etc/app\nmods: [rewrite, ssl]\nrel: etc/app\nslashed: /etc/app/\n",
		"tasks/main.yml": `- name: Conf
  copy: {dest: "{{ conf_dir }}/app.conf", content: x}
- name: Mods
  file: {path: "/etc/app/mods/{{ item }}.load", state: absent}
  with_items: "{{ mods }}"
- name: Relative
  copy: {dest: "{{ rel }}/x", content: x}
- name: Trailing
  copy: {dest: "/srv/{{ slashed }}", content: x}
- name: Not absolute
  file: {path: "srv/{{ conf_dir }}", state: directory}
`,
	}))
	if err != nil {
		t.Fatal(err)
	}
	if res.Converted != 2 || len(res.Review) != 3 {
		t.Fatalf("converted %d, review %+v", res.Converted, res.Review)
	}
	for i, want := range []string{
		`dest refers to the role default "rel" and would be "{{ rel }}/x" with the role's own value of "rel"`,
		`dest refers to the role default "slashed" and would be`,
		`path refers to the role default "conf_dir" and isn't an absolute path`,
	} {
		if !strings.Contains(res.Review[i].Reason, want) {
			t.Errorf("review %d: %s", i, res.Review[i].Reason)
		}
	}
	hcl, vars := string(res.Files["main.circuit.hcl"]), string(res.Files["variables.tf"])
	for _, want := range []string{
		`path    = "${var.conf_dir}/app.conf"`,
		`"/etc/app/mods/${item.value}.load"`,
		`condition     = startswith(var.conf_dir, "/")`,
	} {
		if !strings.Contains(hcl+vars, want) {
			t.Errorf("missing %s in\n%s\n%s", want, hcl, vars)
		}
	}
	if strings.Contains(vars, `endswith(var.conf_dir`) || strings.Contains(vars, `for p in var.mods : startswith`) || strings.Contains(vars, `for p in var.mods : !endswith`) {
		t.Errorf("a rule the path doesn't need:\n%s", vars)
	}
}

// Each written item of a loop must give the step the loop gives it: a
// package name Ansible splits at a comma, or a value the module refuses,
// keeps the task for review.
func TestLiteralLoopItemsAreChecked(t *testing.T) {
	res := convertString(t, `- hosts: all
  tasks:
    - name: Fine
      package: {name: "{{ item }}"}
      loop: [git, jq]
    - name: Comma
      package: {name: "{{ item }}"}
      loop: [git, "a,b"]
    - name: Bad state
      service: {name: nginx, state: "{{ item }}"}
      loop: [started, bogus]
`)
	if res.Converted != 1 || len(res.Review) != 2 {
		t.Fatalf("converted %d, review %+v", res.Converted, res.Review)
	}
	if !strings.Contains(res.Review[0].Reason, `loops over "a,b", which Ansible reads differently`) || !strings.Contains(res.Review[1].Reason, `loops over "bogus", and for that item:`) {
		t.Errorf("review %+v", res.Review)
	}
}

// Ansible fills in a package name's variables before it splits the name at
// commas, so a play var holding two names installs two packages.
func TestPackageNamesSplitAfterVars(t *testing.T) {
	res := convertString(t, `- hosts: all
  vars: {pkgs: "git,jq"}
  tasks:
    - package: {name: "{{ pkgs }}"}
`)
	hcl := string(res.HCL)
	if !strings.Contains(hcl, `name = "git"`) || !strings.Contains(hcl, `name = "jq"`) {
		t.Errorf("converted %d, review %+v\n%s", res.Converted, res.Review, hcl)
	}
}

// A loop over a role default that's a list of maps becomes for_each keyed
// by a field every item needs, with a list(object) variable whose fields
// are the ones the loops read.
func TestRoleLoopOverMaps(t *testing.T) {
	dir := writeRole(t, map[string]string{
		"defaults/main.yml": "admins:\n  - {name: alice, shell: /bin/zsh}\n  - {name: bob}\nextra_users: []\nnameless: [{shell: /bin/sh}]\n",
		"tasks/main.yml": `- name: Admins
  user:
    name: "{{ item.name }}"
    shell: "{{ item.shell | default('/bin/bash') }}"
  with_items: "{{ admins }}"
- name: Extra
  user: {name: "{{ item.login }}"}
  loop: "{{ extra_users }}"
- name: Whole item
  user: {name: "{{ item }}"}
  loop: "{{ admins }}"
- name: Not verbatim
  file: {path: "/home/{{ item.name }}", state: directory}
  loop: "{{ admins }}"
- name: Missing field
  user: {name: "{{ item.name }}"}
  loop: "{{ nameless }}"
`,
	})
	res, err := ConvertRole(dir)
	if err != nil {
		t.Fatal(err)
	}
	flat := func(b []byte) string { return strings.Join(strings.Fields(string(b)), " ") }
	main, vars := flat(res.Files["main.circuit.hcl"]), flat(res.Files["variables.tf"])
	for _, want := range []string{
		"for_each = { for i in var.admins : i.name => i }", "name = item.value.name", "shell = item.value.shell",
		"for_each = { for i in var.extra_users : i.login => i }",
	} {
		if !strings.Contains(main, want) {
			t.Errorf("main.circuit.hcl has no %q:\n%s", want, main)
		}
	}
	for _, want := range []string{
		`type = list(object({ name = string, shell = optional(string, "/bin/bash") }))`,
		`type = list(object({ login = string }))`,
		`length(distinct([for i in var.admins : i.name])) == length(var.admins)`,
	} {
		if !strings.Contains(vars, want) {
			t.Errorf("variables.tf has no %q:\n%s", want, vars)
		}
	}
	var got []string
	for _, r := range res.Review {
		got = append(got, r.Task)
	}
	// A field in a path converts too, now that it's checked as one (#879).
	if res.Converted != 3 || strings.Join(got, ",") != "Whole item,Missing field" || !strings.Contains(main, `path = "/home/${item.value.name}"`) {
		t.Errorf("converted %d, review %+v", res.Converted, res.Review)
	}
}

// Ansible's YAML reads y and n as text, so a bare when on one is true even
// for n. They stay for review, not a bool. No and OFF are booleans.
func TestRoleYAMLBoolLikeAnsible(t *testing.T) {
	res, err := ConvertRole(writeRole(t, map[string]string{
		"defaults/main.yml": "demo_feature: n\ndemo_other: No\ndemo_off: OFF\n",
		"tasks/main.yml": `- name: Only when on
  package: { name: htop }
  when: demo_feature
- name: Other
  package: { name: tree }
  when: demo_other
- name: Off
  package: { name: jq }
  when: not demo_off
`,
	}))
	if err != nil {
		t.Fatal(err)
	}
	hcl, vars := string(res.Files["main.circuit.hcl"]), string(res.Files["variables.tf"])
	if strings.Contains(vars, `variable "demo_feature"`) || strings.Contains(hcl, "var.demo_feature") {
		t.Errorf("n became a variable:\n%s\n%s", vars, hcl)
	}
	for _, w := range []string{"when = var.demo_other", "when = !var.demo_off"} {
		if !strings.Contains(hcl, w) {
			t.Errorf("missing %q:\n%s", w, hcl)
		}
	}
	if res.Converted != 2 || len(res.Review) != 1 {
		t.Errorf("converted %d, review %+v", res.Converted, res.Review)
	}
}

// A when that tests whether a package is installed becomes the step's when
// over the conn3x_packages data source, which replaces package_facts, so
// the dropped task's note doesn't send the step to review.
func TestRolePackagesWhen(t *testing.T) {
	res, err := ConvertRole(writeRole(t, map[string]string{
		"tasks/main.yml": `- name: Facts
  package_facts:
- name: Install nginx
  package: {name: nginx}
  when: "'nginx' not in ansible_facts.packages"
- name: Config
  copy: {dest: /etc/x, content: y}
  when: ansible_facts.packages['bash'] is defined
- name: Both
  copy: {dest: /etc/z, content: y}
  when:
    - ansible_os_family == 'Debian'
    - "'curl' in ansible_facts['packages']"
`,
	}))
	if err != nil {
		t.Fatal(err)
	}
	if res.Converted != 4 || len(res.Review) != 0 {
		t.Fatalf("converted %d, review %+v", res.Converted, res.Review)
	}
	hcl := string(res.Files["main.circuit.hcl"])
	for _, want := range []string{
		`when = !contains(keys(data.conn3x_packages.facts[each.key].packages), "nginx")`,
		`when = contains(keys(data.conn3x_packages.facts[each.key].packages), "bash")`,
		`when = local.os_family[each.key] == "debian" && contains(keys(data.conn3x_packages.facts[each.key].packages), "curl")`,
		`data "conn3x_packages" "facts"`,
		"reads the conn3x_packages data source at plan instead",
	} {
		if !strings.Contains(hcl, want) {
			t.Errorf("missing %s in\n%s", want, hcl)
		}
	}
	if strings.Contains(hcl, "left for review") {
		t.Errorf("the note sends a converted when to review:\n%s", hcl)
	}

	// A template that reads a package's version is still for review, and
	// the note says so; nothing else reads the data source.
	res, err = ConvertRole(writeRole(t, map[string]string{
		"tasks/main.yml": "- package_facts:\n- copy: {dest: /etc/v, content: \"{{ ansible_facts.packages['bash'][0].version }}\"}\n",
	}))
	if err != nil {
		t.Fatal(err)
	}
	hcl = string(res.Files["main.circuit.hcl"])
	if len(res.Review) != 1 || !strings.Contains(hcl, "left for review") || strings.Contains(hcl, `data "conn3x_packages"`) {
		t.Errorf("review %+v\n%s", res.Review, hcl)
	}
}

// A when on the distribution's name or major version reads conn3x_host,
// taking the name from a host object's os first, as the family does.
func TestRoleDistributionWhen(t *testing.T) {
	res, err := ConvertRole(writeRole(t, map[string]string{
		"tasks/main.yml": `- name: Ubuntu only
  copy: {dest: /etc/u, content: x}
  when: ansible_facts.distribution == 'Ubuntu'
- name: Not Amazon, 9 or later
  copy: {dest: /etc/v, content: x}
  when:
    - ansible_distribution != "Amazon"
    - ansible_facts['distribution_major_version'] | int >= 9
- name: Unknown name
  copy: {dest: /etc/w, content: x}
  when: ansible_facts.distribution == 'Gentoo'
`,
	}))
	if err != nil {
		t.Fatal(err)
	}
	if res.Converted != 2 || len(res.Review) != 1 || !strings.Contains(res.Review[0].Reason, "uses when") {
		t.Fatalf("converted %d, review %+v", res.Converted, res.Review)
	}
	hcl := string(res.Files["main.circuit.hcl"])
	for _, want := range []string{
		`when = try(var.hosts[each.key].os, data.conn3x_host.facts[each.key].os_id) == "ubuntu"`,
		`when = try(var.hosts[each.key].os, data.conn3x_host.facts[each.key].os_id) != "amzn" && try(tonumber(split(".", data.conn3x_host.facts[each.key].os_version)[0]), 0) >= 9`,
		`data "conn3x_host" "facts"`,
	} {
		if !strings.Contains(hcl, want) {
			t.Errorf("missing %s in\n%s", want, hcl)
		}
	}
}

// A when built with and, or, not and parentheses from conditions the
// converter reads converts too, and so does a list or text default's
// length. A family test inside one reads local.os_family.
func TestRoleWhenCombinations(t *testing.T) {
	res, err := ConvertRole(writeRole(t, map[string]string{
		"defaults/main.yml": "flag: false\nmode: a\nusers: []\nname_x: ''\n",
		"tasks/main.yml": `- name: Or
  copy: {dest: /etc/a, content: x}
  when: flag or mode == 'b'
- name: Not and parens
  copy: {dest: /etc/b, content: x}
  when: not (flag | bool) and (ansible_facts.os_family == 'Debian' or mode != 'a')
- name: Length
  copy: {dest: /etc/c, content: x}
  when: users | length > 0
- name: Text length
  copy: {dest: /etc/d, content: x}
  when: name_x | length == 0
- name: Unknown part
  copy: {dest: /etc/e, content: x}
  when: flag or nope is defined
`,
	}))
	if err != nil {
		t.Fatal(err)
	}
	if res.Converted != 4 || len(res.Review) != 1 || !strings.Contains(res.Review[0].Task, "Unknown part") {
		t.Fatalf("converted %d, review %+v", res.Converted, res.Review)
	}
	hcl, vars := string(res.Files["main.circuit.hcl"]), string(res.Files["variables.tf"])
	for _, want := range []string{
		`when = (var.flag) || (var.mode == "b")`,
		`when = (!(var.flag)) && ((local.os_family[each.key] == "debian") || (var.mode != "a"))`,
		`when = length(var.users) > 0`,
		`when = length(var.name_x) == 0`,
		`data "conn3x_host" "facts"`,
		`variable "users"`,
	} {
		if !strings.Contains(hcl+vars, want) {
			t.Errorf("missing %s in\n%s\n%s", want, hcl, vars)
		}
	}
}

// A handler's state from a role default follows the variable, which a
// validation keeps to restarted or reloaded, the two a handler does.
func TestRoleHandlerStateFromDefault(t *testing.T) {
	res, err := ConvertRole(writeRole(t, map[string]string{
		"defaults/main.yml": "app_restart_state: restarted\napp_odd_state: started\n",
		"tasks/main.yml":    "- copy: {dest: /etc/app.conf, content: x}\n  notify: restart app\n- copy: {dest: /etc/odd.conf, content: x}\n  notify: odd\n",
		"handlers/main.yml": "- name: restart app\n  service: {name: app, state: \"{{ app_restart_state }}\"}\n- name: odd\n  service: {name: odd, state: \"{{ app_odd_state }}\"}\n",
	}))
	if err != nil {
		t.Fatal(err)
	}
	hcl, vars := string(res.Files["main.circuit.hcl"]), string(res.Files["variables.tf"])
	for _, want := range []string{
		`action = var.app_restart_state == "reloaded" ? "reload" : "restart"`,
		`condition     = contains(["restarted", "reloaded"], var.app_restart_state)`,
	} {
		if !strings.Contains(hcl+vars, want) {
			t.Errorf("missing %s in\n%s\n%s", want, hcl, vars)
		}
	}
	// started isn't something a handler does, so that one stays for review.
	if !strings.Contains(hcl, `Task "odd" (handlers/main.yml line 3) is a handler that doesn't restart or reload a service`) || strings.Contains(vars, "var.app_odd_state)") {
		t.Errorf("odd:\n%s\n%s", hcl, vars)
	}
}

// A handler's when converts as a task's does, the geerlingguy.php shape
// among them; one the converter can't read keeps the handler for review.
func TestRoleHandlerWhen(t *testing.T) {
	res, err := ConvertRole(writeRole(t, map[string]string{
		"defaults/main.yml": "php_enable_webserver: true\nphp_fpm: false\nphp_mode: a\n",
		"tasks/main.yml":    "- copy: {dest: /etc/php.ini, content: x}\n  notify: [restart webserver, restart fpm, restart odd]\n",
		"handlers/main.yml": `- name: restart webserver
  service: {name: apache2, state: restarted}
  when: php_enable_webserver
- name: restart fpm
  service: {name: php-fpm, state: restarted}
  when: [php_fpm | bool, "php_mode == 'a' or php_mode == 'b'"]
- name: restart odd
  service: {name: odd, state: restarted}
  when: some_fact is defined
`,
	}))
	if err != nil {
		t.Fatal(err)
	}
	hcl := string(res.Files["main.circuit.hcl"])
	for _, want := range []string{
		"handler \"restart_webserver\" {\n    when = var.php_enable_webserver\n",
		`when = var.php_fpm && ((var.php_mode == "a") || (var.php_mode == "b"))`,
		`Task "restart odd" (handlers/main.yml line 7) is a handler with a when the converter can't translate yet`,
	} {
		if !strings.Contains(hcl, want) {
			t.Errorf("missing %s in\n%s", want, hcl)
		}
	}
}

// A task's list of whens is ANDed with each condition kept whole, so an or
// inside one doesn't bind into the next.
func TestRoleTaskWhenListKeepsOrTogether(t *testing.T) {
	res, err := ConvertRole(writeRole(t, map[string]string{
		"defaults/main.yml": "flag: false\nmode: a\n",
		"tasks/main.yml":    "- copy: {dest: /etc/x, content: x}\n  when: [\"mode == 'a' or mode == 'b'\", flag | bool]\n",
	}))
	if err != nil {
		t.Fatal(err)
	}
	if hcl := string(res.Files["main.circuit.hcl"]); !strings.Contains(hcl, `when = ((var.mode == "a") || (var.mode == "b")) && var.flag`) {
		t.Errorf("when:\n%s", hcl)
	}
}

// A handler's service named per family in vars/ is looked up by each
// host's family, as a task's value is. One a family doesn't set stays.
func TestRoleHandlerNamePerFamily(t *testing.T) {
	res, err := ConvertRole(writeRole(t, map[string]string{
		"tasks/main.yml":    "- name: Vars\n  include_vars: \"{{ ansible_os_family }}.yml\"\n- name: Conf\n  copy: {dest: /etc/web.conf, content: x}\n  notify: [restart web, restart other]\n",
		"handlers/main.yml": "- name: restart web\n  service: {name: \"{{ web_service }}\", state: restarted}\n- name: restart other\n  service: {name: \"{{ other_service }}\", state: restarted}\n",
		"vars/Debian.yml":   "web_service: apache2\nother_service: x\n",
		"vars/RedHat.yml":   "web_service: httpd\n",
	}))
	if err != nil {
		t.Fatal(err)
	}
	hcl := string(res.Files["main.circuit.hcl"])
	if want := `name   = { debian = "apache2", redhat = "httpd" }[local.os_family[each.key]]`; !strings.Contains(hcl, want) || !strings.Contains(hcl, `data "conn3x_host" "facts"`) {
		t.Errorf("missing %s or the facts in\n%s", want, hcl)
	}
	if len(res.Review) < 1 || !strings.Contains(res.Review[0].Reason, `refers to "other_service", which vars/RedHat.yml doesn't set as plain text`) {
		t.Errorf("review %+v", res.Review)
	}
}

// A set_fact of plain text with role defaults in it is written out where
// it's used, so the default is held to the rules there; one set twice, or
// under a when, stays for review.
func TestRolePlainFacts(t *testing.T) {
	res, err := ConvertRole(writeRole(t, map[string]string{
		"defaults/main.yml": "app_dir: /opt/app\nflag: true\n",
		"tasks/main.yml": `- name: Script path
  set_fact:
    app_script: "{{ app_dir }}/run.sh"
    app_conf: "{{ app_dir }}/app.conf"
- name: Twice
  set_fact:
    twice: a
- name: Twice again
  set_fact:
    twice: b
- name: Conditional
  set_fact:
    maybe: "{{ app_dir }}/x"
  when: flag | bool
- name: Script
  copy: {dest: "{{ app_script }}", content: x}
- name: Twice used
  copy: {dest: /etc/t, content: "{{ twice }}"}
`,
	}))
	if err != nil {
		t.Fatal(err)
	}
	hcl, vars := string(res.Files["main.circuit.hcl"]), string(res.Files["variables.tf"])
	for _, want := range []string{
		`names app_script and app_conf: the steps below write its text where they use it`,
		`path    = "${var.app_dir}/run.sh"`,
		`condition     = startswith(var.app_dir, "/")`,
	} {
		if !strings.Contains(hcl+vars, want) {
			t.Errorf("missing %s in\n%s\n%s", want, hcl, vars)
		}
	}
	reasons := ""
	for _, r := range res.Review {
		reasons += r.Task + ": " + r.Reason + "\n"
	}
	if !strings.Contains(reasons, "Twice used: content refers to \"twice\"") || !strings.Contains(reasons, "Conditional:") {
		t.Errorf("review:\n%s", reasons)
	}
}

// An include_vars with_first_found over per-OS files gives each family the
// file all its distributions would load, and it can sit in an imported file.
// A list where the pick depends on the version stays for review.
func TestRoleFirstFoundVars(t *testing.T) {
	res, err := ConvertRole(writeRole(t, map[string]string{
		"tasks/main.yml": "- import_tasks: vars.yml\n- name: Web\n  package: {name: \"{{ web_pkg }}\"}\n",
		"tasks/vars.yml": `- name: Load vars
  include_vars: "{{ item }}"
  with_first_found:
    - "{{ ansible_facts.distribution }}.yml"
    - "{{ ansible_facts.os_family }}.yml"
    - default.yml
`,
		"vars/Debian.yml":  "web_pkg: apache2\n",
		"vars/RedHat.yml":  "web_pkg: httpd\n",
		"vars/default.yml": "web_pkg: other\n",
	}))
	if err != nil {
		t.Fatal(err)
	}
	hcl := string(res.Files["main.circuit.hcl"])
	if res.Converted != 2 || len(res.Review) != 0 || !strings.Contains(hcl, `{ debian = "apache2", redhat = "httpd" }[local.os_family[each.key]]`) {
		t.Fatalf("converted %d, review %+v\n%s", res.Converted, res.Review, hcl)
	}

	// Ubuntu-24.04.yml means what Ubuntu loads depends on its version, so
	// the value is looked up by the file each host loads, worked out at plan.
	// Ubuntu-16.04.yml is older than any release the converter reads.
	res, err = ConvertRole(writeRole(t, map[string]string{
		"tasks/main.yml": `- include_vars: "{{ item }}"
  with_first_found:
    - "{{ ansible_facts.distribution + '-' + ansible_facts.distribution_version }}.yml"
    - "{{ ansible_facts.os_family }}-{{ ansible_facts.distribution_major_version }}.yml"
    - default.yml
- package: {name: "{{ web_pkg }}"}
`,
		"vars/Ubuntu-24.04.yml": "web_pkg: apache2\n",
		"vars/Ubuntu-16.04.yml": "web_pkg: old\n",
		"vars/RedHat-9.yml":     "web_pkg: httpd\n",
		"vars/default.yml":      "web_pkg: other\n",
	}))
	if err != nil {
		t.Fatal(err)
	}
	hcl = string(res.Files["main.circuit.hcl"])
	for _, want := range []string{
		`name = { "debian/Ubuntu-24.04.yml" = "apache2", "debian/default.yml" = "other", "redhat/RedHat-9.yml" = "httpd", "redhat/default.yml" = "other" }[local.vars_file[each.key]]`,
		`vars_files = ["RedHat-9.yml", "Ubuntu-16.04.yml", "Ubuntu-24.04.yml", "default.yml"]`,
		`try([for f in ["${local.os_distribution[name]}-${local.os_version[name]}.yml", "${local.os_family_name[name]}-${split(".", data.conn3x_host.facts[name].os_version)[0]}.yml", "default.yml"] : f if contains(local.vars_files, f)][0], ""),`,
	} {
		if !strings.Contains(hcl, want) {
			t.Errorf("version-dependent: missing %s in\n%s", want, hcl)
		}
	}
	if res.Converted != 2 || len(res.Review) != 0 {
		t.Fatalf("version-dependent: converted %d, review %+v", res.Converted, res.Review)
	}

	// A file per minor release stays for review: the converter would need
	// the values for every minor release, and doesn't list them.
	res, err = ConvertRole(writeRole(t, map[string]string{
		"tasks/main.yml": `- include_vars: "{{ item }}"
  with_first_found:
    - "{{ ansible_facts.distribution }}-{{ ansible_facts.distribution_version }}.yml"
    - default.yml
- package: {name: "{{ web_pkg }}"}
`,
		"vars/Rocky-9.4.yml": "web_pkg: httpd\n",
		"vars/default.yml":   "web_pkg: other\n",
	}))
	if err != nil {
		t.Fatal(err)
	}
	if res.Converted != 0 || len(res.Review) != 2 {
		t.Fatalf("minor version: converted %d, review %+v", res.Converted, res.Review)
	}
}

// The files and skip form of with_first_found: a family with no file loads
// nothing when skip is set, so a task using its values is left for review,
// and without skip the loop is. Anything that changes where it looks, or a
// family whose distributions load different files, stays for review.
func TestRoleFirstFoundFilesAndSkip(t *testing.T) {
	convert := func(loop string, files ...string) Result {
		t.Helper()
		role := map[string]string{"tasks/main.yml": "- include_vars: \"{{ item }}\"\n  with_first_found:" + loop + "\n- package: {name: \"{{ web_pkg }}\"}\n"}
		for _, f := range files {
			role["vars/"+f] = "web_pkg: apache2\n"
		}
		res, err := ConvertRole(writeRole(t, role))
		if err != nil {
			t.Fatal(err)
		}
		return res
	}
	res := convert("\n    files: ['{{ ansible_os_family }}.yml']\n    skip: true", "Debian.yml")
	if res.Converted != 1 || len(res.Review) != 1 || !strings.Contains(res.Review[0].Reason, "Ansible would stop on RedHat hosts") {
		t.Errorf("skip: converted %d, review %+v", res.Converted, res.Review)
	}
	if res := convert("\n    files: ['{{ ansible_os_family }}.yml']", "Debian.yml"); res.Converted != 0 || len(res.Review) != 2 {
		t.Errorf("no skip: converted %d, review %+v", res.Converted, res.Review)
	}
	for name, loop := range map[string]string{
		"paths":            "\n    - files: [Debian.yml]\n      paths: [/etc]",
		"a nested list":    "\n    - files: [[Debian.yml]]",
		"a list in a list": "\n    - [Debian.yml]",
		"a brace":          "\n    - '{{ ansible_os_family }}}.yml'",
	} {
		if res := convert(loop, "Debian.yml", "Ubuntu.yml", "RedHat.yml"); res.Converted != 0 || len(res.Review) != 2 {
			t.Errorf("%s: converted %d, review %+v", name, res.Converted, res.Review)
		}
	}
}

// Several include_vars load in order, a later file's keys winning, and an
// include with a when on the family or distribution loads only there.
func TestRoleLayeredVars(t *testing.T) {
	// geerlingguy.php: the family file, then a release file over it.
	res, err := ConvertRole(writeRole(t, map[string]string{
		"tasks/main.yml": `- include_vars: "{{ ansible_facts.os_family }}.yml"
- include_vars: "{{ item }}"
  with_first_found:
    - files:
        - "{{ ansible_facts.distribution }}-{{ ansible_facts.distribution_major_version }}.yml"
      skip: true
- package: {name: "{{ pkg }}"}
- service: {name: "{{ svc }}", state: started}
`,
		"vars/Debian.yml":    "pkg: php\nsvc: php-fpm\n",
		"vars/Debian-13.yml": "pkg: php8.4\n",
		"vars/RedHat.yml":    "pkg: php\nsvc: php-fpm\n",
	}))
	if err != nil {
		t.Fatal(err)
	}
	hcl := string(res.Files["main.circuit.hcl"])
	for _, want := range []string{
		`name = { "debian/Debian.yml" = "php", "debian/Debian.yml+Debian-13.yml" = "php8.4", "redhat/RedHat.yml" = "php" }[local.vars_file[each.key]]`,
		// The layer doesn't set svc, so the family file's value holds.
		`name  = "php-fpm"`,
		`try([for f in ["${local.os_family_name[name]}.yml"] : f if contains(local.vars_files, f)][0], ""),`,
	} {
		if !strings.Contains(hcl, want) {
			t.Errorf("layered: missing %s in\n%s", want, hcl)
		}
	}
	if res.Converted != 4 || len(res.Review) != 0 {
		t.Errorf("layered: converted %d, review %+v", res.Converted, res.Review)
	}

	// geerlingguy.postgresql: one include per family, the version read
	// through split. No file for Fedora 44 or 45, so those hosts would stop
	// at the include, and the values are looked up per file.
	role := map[string]string{
		"tasks/main.yml": `- include_vars: "{{ ansible_facts.distribution }}-{{ ansible_facts.distribution_version.split('.')[0] }}.yml"
  when: ansible_facts.os_family == 'Debian'
- include_vars: "{{ ansible_facts.os_family }}-{{ ansible_facts.distribution_version.split('.')[0] }}.yml"
  when:
    - ansible_facts.os_family == 'RedHat'
    - ansible_facts.distribution != 'Fedora'
- include_vars: "{{ ansible_facts.distribution }}-{{ ansible_facts.distribution_version.split('.')[0] }}.yml"
  when: ansible_facts.distribution == 'Fedora'
- package: {name: "{{ pkg }}"}
`,
	}
	for _, f := range []string{"Debian-11", "Debian-12", "Debian-13", "Ubuntu-20", "Ubuntu-22", "Ubuntu-24", "Ubuntu-26", "RedHat-8", "RedHat-9", "RedHat-10", "Fedora-40", "Fedora-41", "Fedora-42", "Fedora-43"} {
		role["vars/"+f+".yml"] = "pkg: postgresql-" + strings.ToLower(f) + "\n"
	}
	res, err = ConvertRole(writeRole(t, role))
	if err != nil {
		t.Fatal(err)
	}
	hcl = string(res.Files["main.circuit.hcl"])
	for _, want := range []string{
		`"redhat/RedHat-10.yml" = "postgresql-redhat-10"`,
		`"redhat/Fedora-43.yml" = "postgresql-fedora-43"`,
		`contains(["Debian"], local.os_family_name[name]) ? try(`,
		`contains(["RedHat"], local.os_family_name[name]) && !contains(["Fedora"], local.os_distribution[name]) ? try(`,
	} {
		if !strings.Contains(hcl, want) {
			t.Errorf("per family: missing %s in\n%s", want, hcl)
		}
	}
	if res.Converted != 4 || len(res.Review) != 0 {
		t.Errorf("per family: converted %d, review %+v", res.Converted, res.Review)
	}
}
