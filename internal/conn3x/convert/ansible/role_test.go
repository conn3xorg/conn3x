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
		`path refers to the role default "mixed_conf_dir"`,
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
	// The import behind a family when converts, as each task given it.
	if res.Converted != 1 || len(res.Review) != 11 {
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
	if !strings.Contains(string(res.HCL), `name   = "nginx"`) || len(res.Review) != 2 || !strings.Contains(res.Review[0].Reason, "uses when") {
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
	for _, gone := range []string{`variable "vhosts"`, `variable "twice"`, `variable "unused"`} {
		if strings.Contains(vars, gone) {
			t.Errorf("variables.tf has %s:\n%s", gone, vars)
		}
	}
	var tasks []string
	for _, r := range res.Review {
		tasks = append(tasks, r.Task)
	}
	if strings.Join(tasks, ",") != "Vhosts,Twice,As a value" {
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

// with_items over a written list of plain values is loop over it; a list
// of maps, or both loop and with_items, stays for review.
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
	if !strings.Contains(hcl, `for_each = ["git", "jq"]`) || res.Converted != 1 || len(res.Review) != 2 {
		t.Errorf("converted %d, review %+v\n%s", res.Converted, res.Review, hcl)
	}
	if len(res.Review) == 2 && !strings.Contains(res.Review[1].Reason, "both loop and with_items") {
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
	if res.Converted != 1 || len(res.Review) != 1 || !strings.Contains(res.Review[0].Reason, `path uses item from the role default "dirs"`) {
		t.Errorf("converted %d, review %+v", res.Converted, res.Review)
	}
	if vars := string(res.Files["variables.tf"]); !strings.Contains(vars, `alltrue([for p in var.pkgs : !strcontains(p, ",")])`) {
		t.Errorf("no comma check on pkgs:\n%s", vars)
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
	if res.Converted != 2 || strings.Join(got, ",") != "Whole item,Not verbatim,Missing field" {
		t.Errorf("converted %d, review %+v", res.Converted, res.Review)
	}
}
