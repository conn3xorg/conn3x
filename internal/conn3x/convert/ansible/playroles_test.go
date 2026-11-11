// Copyright (c) The Conn3x Authors
// SPDX-License-Identifier: MPL-2.0

package ansible

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// The play's pre_tasks, its roles, its tasks and an include_role in them
// become circuits and modules that each wait for the one before, and the
// role converts once into a circuit directory both calls share.
func TestConvertPlayRoles(t *testing.T) {
	res, err := ConvertWith(filepath.Join("testdata", "playroles", "site.yml"), Options{Roles: true})
	if err != nil {
		t.Fatal(err)
	}
	golden := filepath.Join("testdata", "playroles", "site.tf")
	if *update {
		if err := os.WriteFile(golden, res.HCL, 0o644); err != nil {
			t.Fatal(err)
		}
	}
	want, err := os.ReadFile(golden)
	if err != nil {
		t.Fatal(err)
	}
	if string(want) != string(res.HCL) {
		t.Errorf("site.tf differs from %s (run with -update to accept):\n%s", golden, res.HCL)
	}
	for _, p := range []string{"main.circuit.hcl", "variables.tf", "outputs.tf", "README.md"} {
		if res.Files["circuit-web/"+p] == nil {
			t.Errorf("circuit-web/%s wasn't written", p)
		}
	}
	if len(res.Files) != 4 {
		t.Errorf("wrote %d files, want the role's 4 once", len(res.Files))
	}
	// curl, the motd and the include_role, then the role's two tasks.
	if res.Converted != 5 {
		t.Errorf("converted %d, want 5", res.Converted)
	}
	if len(res.Review) != 2 || !strings.Contains(res.Review[0].Reason, "passes web_extra") || !strings.Contains(res.Review[1].Reason, "isn't at roles/missing") {
		t.Errorf("review: %+v", res.Review)
	}
}

// Without Options.Roles there's nowhere to write a role's circuit, so the
// play's roles are left for review, saying how to convert them.
func TestConvertPlayRolesNeedOut(t *testing.T) {
	res, err := Convert(filepath.Join("testdata", "playroles", "site.yml"))
	if err != nil {
		t.Fatal(err)
	}
	if len(res.Files) != 0 || !strings.Contains(string(res.HCL), "convert with -out") || strings.Contains(string(res.HCL), "module ") {
		t.Errorf("files %d:\n%s", len(res.Files), res.HCL)
	}
}

// A role call that sets what the converter can't carry over, such as a
// when or a tasks_from the role hasn't got, is left for review where it was.
func TestConvertPlayRolesRefuses(t *testing.T) {
	dir := t.TempDir()
	if err := os.CopyFS(filepath.Join(dir, "roles"), os.DirFS(filepath.Join("testdata", "playroles", "roles"))); err != nil {
		t.Fatal(err)
	}
	play := "- hosts: all\n  roles:\n    - role: web\n      when: x\n  tasks:\n    - include_role:\n        name: web\n        tasks_from: other\n"
	if err := os.WriteFile(filepath.Join(dir, "p.yml"), []byte(play), 0o644); err != nil {
		t.Fatal(err)
	}
	res, err := ConvertWith(filepath.Join(dir, "p.yml"), Options{Roles: true})
	if err != nil {
		t.Fatal(err)
	}
	if len(res.Review) != 2 || !strings.Contains(res.Review[0].Reason, "sets when on the role") || !strings.Contains(res.Review[1].Reason, "runs the role web from tasks/other, which isn't in the role") {
		t.Errorf("review: %+v", res.Review)
	}
	if strings.Contains(string(res.HCL), "module ") {
		t.Errorf("wrote a module:\n%s", res.HCL)
	}
}

// include_role's tasks_from and defaults_from start the role from those
// files, which makes it another circuit directory beside the one a plain
// call uses. A name with no extension finds the .yml, as in Ansible, and one
// outside the role, or a Jinja expression, is left for review.
func TestConvertPlayRolesEntryFiles(t *testing.T) {
	play := "- hosts: all\n  tasks:\n    - include_role:\n        name: web\n" +
		"    - import_role:\n        name: web\n        tasks_from: install\n        defaults_from: tls.yml\n" +
		"    - include_role:\n        name: web\n        tasks_from: install.yml\n        defaults_from: tls\n"
	res := convertPlay(t, play)
	if len(res.Review) != 0 {
		t.Fatalf("review: %+v", res.Review)
	}
	plain, entry := string(res.Files["circuit-web/main.circuit.hcl"]), string(res.Files["circuit-web-install-tls/main.circuit.hcl"])
	if !strings.Contains(plain, "nginx") || strings.Contains(plain, "nginx-light") {
		t.Errorf("the plain call's circuit should run tasks/main.yml:\n%s", plain)
	}
	if !strings.Contains(entry, "(from tasks/install.yml, defaults/tls.yml)") || !strings.Contains(entry, "nginx-light") || strings.Contains(entry, "Listen port") {
		t.Errorf("the entry call's circuit should run tasks/install.yml:\n%s", entry)
	}
	if v := string(res.Files["circuit-web-install-tls/variables.tf"]); !strings.Contains(v, "default     = 8443") {
		t.Errorf("the entry call's default should come from defaults/tls.yml:\n%s", v)
	}
	if n := strings.Count(string(res.HCL), "source = \"./circuit-web-install-tls\""); n != 2 {
		t.Errorf("both entry calls should use one circuit directory, got %d:\n%s", n, res.HCL)
	}

	for opt, want := range map[string]string{
		"tasks_from: ../../x":    "which isn't a file inside the role's tasks/",
		"tasks_from: /etc/x":     "which isn't a file inside the role's tasks/",
		"vars_from: \"{{ f }}\"": "sets vars_from with a Jinja expression",
		"handlers_from: nope":    "runs the role web from handlers/nope, which isn't in the role",
	} {
		res := convertPlay(t, "- hosts: all\n  tasks:\n    - include_role:\n        name: web\n        "+opt+"\n")
		if strings.Contains(string(res.HCL), "module ") || len(res.Review) != 1 || !strings.Contains(res.Review[0].Reason, want) {
			t.Errorf("%s: review %+v", opt, res.Review)
		}
	}
}

// A looped include_role runs the role once per item, one after another as
// Ansible does, so each item is a module waiting for the one before, not a
// for_each. The role converts into its own directory with the loop
// variable required, and a plain call keeps the directory without it.
func TestConvertPlayRolesLoop(t *testing.T) {
	play := "- hosts: all\n  tasks:\n    - include_role:\n        name: web\n" +
		"    - include_role:\n        name: web\n      loop: [80, 8080]\n      loop_control:\n        loop_var: web_port\n        label: port\n"
	res := convertPlay(t, play)
	if len(res.Review) != 0 || res.Converted == 0 {
		t.Fatalf("review: %+v", res.Review)
	}
	hcl := string(res.HCL)
	for _, want := range []string{
		"module \"web\" {\n  source = \"./circuit-web\"",
		"module \"web_2\" {\n  source = \"./circuit-web-each\"", "web_port = 80\n", "depends_on = [module.web]",
		"module \"web_3\" {\n  source = \"./circuit-web-each\"", "web_port = 8080", "depends_on = [module.web_2]",
	} {
		if !strings.Contains(hcl, want) {
			t.Errorf("output lacks %q:\n%s", want, hcl)
		}
	}
	if strings.Contains(hcl, "for_each") {
		t.Errorf("a looped call shouldn't use for_each:\n%s", hcl)
	}
	v := string(res.Files["circuit-web-each/variables.tf"])
	if i := strings.Index(v, "variable \"web_port\""); i < 0 || strings.Contains(v[i:], "default") {
		t.Errorf("the looped circuit should require web_port:\n%s", v)
	}
	if v := string(res.Files["circuit-web/variables.tf"]); !strings.Contains(v, "default     = 80") {
		t.Errorf("the plain circuit should keep web_port's default:\n%s", v)
	}

	for task, want := range map[string]string{
		"import_role:\n        name: web\n      loop: [a]":                                                "sets loop on import_role",
		"include_role:\n        name: web\n      loop: \"{{ ports }}\"":                                   "uses a loop over a variable",
		"include_role:\n        name: web\n      loop: [{a: 1}]":                                          "loops over items with fields",
		"include_role:\n        name: web\n      loop: []":                                                "loops over no items",
		"include_role:\n        name: web\n      loop: [a]\n      loop_control:\n        pause: 3":        "sets pause in loop_control",
		"include_role:\n        name: web\n      loop: [a]\n      loop_control:\n        loop_var: hosts": "sets loop_var to a name the circuit can't use",
	} {
		res := convertPlay(t, "- hosts: all\n  tasks:\n    - "+task+"\n")
		if strings.Contains(string(res.HCL), "module ") || len(res.Review) != 1 || !strings.Contains(res.Review[0].Reason, want) {
			t.Errorf("%s: review %+v", task, res.Review)
		}
	}
}

// convertPlay writes play beside a copy of the fixture's roles, adding
// extra roles as copies of web, and converts it with Options.Roles.
func convertPlay(t *testing.T, play string, extra ...string) Result {
	t.Helper()
	dir := t.TempDir()
	for _, name := range append([]string{"web"}, extra...) {
		if err := os.CopyFS(filepath.Join(dir, "roles", name), os.DirFS(filepath.Join("testdata", "playroles", "roles", "web"))); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.WriteFile(filepath.Join(dir, "p.yml"), []byte(play), 0o644); err != nil {
		t.Fatal(err)
	}
	res, err := ConvertWith(filepath.Join(dir, "p.yml"), Options{Roles: true})
	if err != nil {
		t.Fatal(err)
	}
	return res
}

// Each of these would have run the role differently from Ansible, so the
// call is left for review instead of becoming a module.
func TestConvertPlayRolesRefusesWhatChangesTheRun(t *testing.T) {
	for play, want := range map[string]string{
		"- hosts: all\n  tasks:\n    - include_role:\n        name: web\n      with_items: [a, b]\n": "sets with_items on include_role",
		"- hosts: all\n  roles:\n    - role: web\n      become: \"{{ b }}\"\n":                       "sets become to something other than true or false",
		"- hosts: all\n  roles:\n    - role: web\n      tasks_from: other\n":                         "sets tasks_from on the role",
		"- hosts: all\n  no_log: true\n  roles:\n    - web\n":                                        "sets no_log",
		"- hosts: all\n  become: true\n  become_user: deploy\n  roles:\n    - web\n":                 "which its circuit wouldn't keep",
	} {
		res := convertPlay(t, play)
		if strings.Contains(string(res.HCL), "module ") || len(res.Review) == 0 || !strings.Contains(res.Review[len(res.Review)-1].Reason, want) {
			t.Errorf("%s: review %+v\n%s", play, res.Review, res.HCL)
		}
	}
}

// Roles whose names slug alike get their own directories, and a circuit
// split from one play doesn't take a later play's name.
func TestConvertPlayRolesNamesDontCollide(t *testing.T) {
	res := convertPlay(t, "- hosts: web\n  roles:\n    - web\n    - x.web\n    - web_2\n  tasks:\n    - name: After\n      package:\n        name: curl\n- name: web_2\n  hosts: other\n  tasks:\n    - name: Other\n      package:\n        name: tree\n", "x.web", "web_2")
	hcl := string(res.HCL)
	for _, dir := range []string{"circuit-web", "circuit-web_2", "circuit-web-2"} {
		if res.Files[dir+"/main.circuit.hcl"] == nil || !strings.Contains(hcl, `"./`+dir+`"`) {
			t.Errorf("no %s:\n%s", dir, hcl)
		}
	}
	if strings.Count(hcl, `circuit "web_2" {`) != 1 {
		t.Errorf("circuit names collide:\n%s", hcl)
	}
}

// A circuit after a role waits for it, and the role waits for the circuit
// before it, handlers included, as Ansible flushes them between sections.
// A handler that can't convert is listed for review once, though each
// circuit carries the play's handlers.
func TestConvertPlayRolesWaitsForHandlers(t *testing.T) {
	res := convertPlay(t, "- hosts: web\n  pre_tasks:\n    - name: Conf\n      copy:\n        content: x\n        dest: /etc/x\n      notify: Restart x\n  roles:\n    - web\n  tasks:\n    - name: After\n      package:\n        name: curl\n  handlers:\n    - name: Restart x\n      service:\n        name: x\n        state: restarted\n    - name: Odd\n      command: /bin/true\n")
	hcl := string(res.HCL)
	if !strings.Contains(hcl, "depends_on = [conn3x_file.web__conf, conn3x_service_action.web__restart_x]") || !strings.Contains(hcl, "depends_on = [module.web]") {
		t.Errorf("waits:\n%s", hcl)
	}
	odd := 0
	for _, r := range res.Review {
		if r.Task == "Odd" {
			odd++
		}
	}
	if odd != 1 {
		t.Errorf("the handler is listed %d times: %+v", odd, res.Review)
	}
}

// convertWithMeta is convertPlay with each role given a meta/main.yml.
func convertWithMeta(t *testing.T, play string, meta map[string]string) Result {
	t.Helper()
	dir := t.TempDir()
	for name, m := range meta {
		if err := os.CopyFS(filepath.Join(dir, "roles", name), os.DirFS(filepath.Join("testdata", "playroles", "roles", "web"))); err != nil {
			t.Fatal(err)
		}
		if m == "" {
			continue
		}
		if err := os.MkdirAll(filepath.Join(dir, "roles", name, "meta"), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(dir, "roles", name, "meta", "main.yml"), []byte(m), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.WriteFile(filepath.Join(dir, "p.yml"), []byte(play), 0o644); err != nil {
		t.Fatal(err)
	}
	res, err := ConvertWith(filepath.Join(dir, "p.yml"), Options{Roles: true})
	if err != nil {
		t.Fatal(err)
	}
	return res
}

// A role's meta/ dependencies run before it, each as its own module with
// the vars meta/ passes, and a dependency the play already ran with the
// same vars runs once.
func TestConvertPlayRolesDependencies(t *testing.T) {
	res := convertWithMeta(t, "- hosts: web\n  roles:\n    - common\n    - app\n    - db\n", map[string]string{
		"common": "",
		"app":    "dependencies:\n  - common\n",
		"db":     "dependencies:\n  - role: common\n    web_port: 81\n",
	})
	hcl := string(res.HCL)
	order := []string{`module "common" {`, `module "app" {`, "depends_on = [module.common]", `module "common_2" {`, "web_port = 81", "depends_on = [module.app]", `module "db" {`, "depends_on = [module.common_2]"}
	at := 0
	for _, s := range order {
		i := strings.Index(hcl[at:], s)
		if i < 0 {
			t.Fatalf("%q missing or out of order:\n%s", s, hcl)
		}
		at += i
	}
	if strings.Count(hcl, "module \"") != 4 || len(res.Review) != 0 {
		t.Errorf("review %+v:\n%s", res.Review, hcl)
	}
	if strings.Contains(string(res.Files["circuit-app/main.circuit.hcl"]), "dependencies") {
		t.Errorf("circuit-app still says to convert its dependencies:\n%s", res.Files["circuit-app/main.circuit.hcl"])
	}
}

// A dependency that can't convert, or a role that depends on itself, keeps
// the call for review.
func TestConvertPlayRolesDependenciesRefused(t *testing.T) {
	for want, meta := range map[string]map[string]string{
		"whose dependency can't convert: it runs the role gone": {"app": "dependencies:\n  - gone\n"},
		"depends on itself": {"app": "dependencies:\n  - b\n", "b": "dependencies:\n  - app\n"},
	} {
		res := convertWithMeta(t, "- hosts: web\n  roles:\n    - app\n", meta)
		if strings.Contains(string(res.HCL), "module ") || len(res.Review) == 0 || !strings.Contains(res.Review[0].Reason, want) {
			t.Errorf("%s: review %+v\n%s", want, res.Review, res.HCL)
		}
	}
}

// A role whose meta/ sets allow_duplicates runs each time it's listed, and
// two calls that pass different lists aren't the same call.
func TestConvertPlayRolesRunsAgain(t *testing.T) {
	res := convertWithMeta(t, "- hosts: web\n  roles:\n    - common\n    - common\n    - role: web\n      vars:\n        ports: [80]\n    - role: web\n      vars:\n        ports: [443]\n", map[string]string{
		"common": "allow_duplicates: true\n",
		"web":    "",
	})
	hcl := string(res.HCL)
	if strings.Count(hcl, `source = "./circuit-common"`) != 2 || strings.Count(hcl, `source = "./circuit-web"`) != 2 {
		t.Errorf("runs:\n%s", hcl)
	}
}

// What a dependency in meta/ passes is reported against meta/, and a
// dependency of a role that can't be called isn't written.
func TestConvertPlayRolesDependencyFiles(t *testing.T) {
	res := convertWithMeta(t, "- hosts: web\n  roles:\n    - app\n    - db\n", map[string]string{
		"common": "",
		"app":    "dependencies:\n  - role: common\n    vars:\n      web_port: \"{{ p }}\"\n",
		"db":     "dependencies:\n  - other\n  - gone\n",
		"other":  "",
	})
	if len(res.Review) != 2 || res.Review[0].File != "roles/app/meta/main.yml" || !strings.Contains(res.Review[1].Reason, "runs the role gone") {
		t.Errorf("review: %+v", res.Review)
	}
	if res.Files["circuit-other/main.circuit.hcl"] != nil || res.Files["circuit-common/main.circuit.hcl"] == nil {
		t.Errorf("files: %v", len(res.Files))
	}
}

// A role beside the playbook, not in roles/, is found as Ansible finds it.
func TestConvertPlayRolesBesideThePlaybook(t *testing.T) {
	dir := t.TempDir()
	if err := os.CopyFS(filepath.Join(dir, "web"), os.DirFS(filepath.Join("testdata", "playroles", "roles", "web"))); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "p.yml"), []byte("- hosts: web\n  roles:\n    - web\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	res, err := ConvertWith(filepath.Join(dir, "p.yml"), Options{Roles: true})
	if err != nil || len(res.Review) != 0 || !strings.Contains(string(res.HCL), `module "web"`) {
		t.Fatalf("%v %+v\n%s", err, res.Review, res.HCL)
	}
}

// A when on a role call that tests the host's family filters the hosts the
// call passes, as Ansible skips the role on a host where it's false, reading
// each host's family from one conn3x_host data source for the play's hosts.
// A when every Conn3x host meets passes them all, one none meets is left
// for review, and the role's meta/ dependencies get the same filter.
func TestConvertPlayRolesWhen(t *testing.T) {
	dir := t.TempDir()
	if err := os.CopyFS(filepath.Join(dir, "roles"), os.DirFS(filepath.Join("testdata", "playroles", "roles"))); err != nil {
		t.Fatal(err)
	}
	for name, content := range map[string]string{
		"roles/base/tasks/main.yml": "- name: Base\n  package:\n    name: curl\n",
		"roles/web/meta/main.yml":   "dependencies:\n  - base\n",
		"p.yml": `- hosts: web
  roles:
    - role: web
      when: ansible_os_family == 'Debian'
  tasks:
    - include_role:
        name: web
      when: ansible_facts['os_family'] in ['RedHat']
    - include_role:
        name: web
      when: ansible_os_family != 'Archlinux'
    - include_role:
        name: web
      when: ansible_os_family == 'Archlinux'
`,
	} {
		path := filepath.Join(dir, filepath.FromSlash(name))
		if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	res, err := ConvertWith(filepath.Join(dir, "p.yml"), Options{Roles: true})
	if err != nil {
		t.Fatal(err)
	}
	hcl := string(res.HCL)
	if n := strings.Count(hcl, `data "conn3x_host" "web_hosts"`); n != 1 {
		t.Errorf("%d facts data sources, want one for the play's hosts:\n%s", n, hcl)
	}
	for _, want := range []string{
		"host = try(each.value.address, each.value)",
		`hosts = { for h, addr in var.web_hosts : h => addr if data.conn3x_host.web_hosts[h].os_family == "debian" }`,
		`hosts = { for h, addr in var.web_hosts : h => addr if data.conn3x_host.web_hosts[h].os_family == "redhat" }`,
	} {
		if !strings.Contains(strings.Join(strings.Fields(hcl), " "), want) {
			t.Errorf("output lacks %q:\n%s", want, hcl)
		}
	}
	// base for the Debian call, then web; base again for the Red Hat call,
	// since the filter makes it a different call; the != call passes every
	// host, and base hasn't run unfiltered yet, so it runs again.
	if n := strings.Count(hcl, `source = "./circuit-base"`); n != 3 {
		t.Errorf("base is called %d times, want once per distinct filter:\n%s", n, hcl)
	}
	if n := strings.Count(hcl, "\n  hosts                = var.web_hosts\n"); n != 2 {
		t.Errorf("%d unfiltered calls, want base and web for the != call:\n%s", n, hcl)
	}
	if len(res.Review) != 1 || !strings.Contains(res.Review[0].Reason, "no Debian or Red Hat family host meets") {
		t.Errorf("review: %+v", res.Review)
	}
}

// A role call in a file pulled in with import_tasks, even two imports deep,
// takes its place in the play's order, as it would written in place. The
// tasks around it still come from their own file, so what's left for review
// names that file. An import that can't be inlined keeps its call for
// review, and one with no role call converts as before.
func TestConvertPlayRolesInImports(t *testing.T) {
	dir := t.TempDir()
	if err := os.CopyFS(filepath.Join(dir, "roles"), os.DirFS(filepath.Join("testdata", "playroles", "roles"))); err != nil {
		t.Fatal(err)
	}
	for name, content := range map[string]string{
		"p.yml": `- hosts: web
  tasks:
    - name: Before
      copy: {content: "a\n", dest: /etc/a}
    - import_tasks: more.yml
    - name: After
      copy: {content: "c\n", dest: /etc/c}
    - import_tasks: plain.yml
    - import_tasks: deeper.yml
      when: x
  handlers:
    - name: Reload app
      service: {name: app, state: reloaded}
`,
		"more.yml": `- name: In the import
  copy: {content: "b\n", dest: /etc/b}
  notify: Reload app
- import_tasks: deeper.yml
- name: Odd one
  community.example.nothing: {}
`,
		"deeper.yml": "- include_role:\n    name: web\n",
		"plain.yml":  "- name: Plain\n  copy: {content: \"d\\n\", dest: /etc/d}\n",
	} {
		if err := os.WriteFile(filepath.Join(dir, name), []byte(content), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	res, err := ConvertWith(filepath.Join(dir, "p.yml"), Options{Roles: true})
	if err != nil {
		t.Fatal(err)
	}
	hcl := strings.Join(strings.Fields(string(res.HCL)), " ")
	order := []string{`path = "/etc/a"`, `path = "/etc/b"`, `module "web"`, "Odd one", `path = "/etc/c"`, `path = "/etc/d"`}
	last := -1
	for _, w := range order {
		i := strings.Index(hcl, w)
		if i < 0 || i < last {
			t.Fatalf("%q is missing or out of order:\n%s", w, hcl)
		}
		last = i
	}
	if n := strings.Count(hcl, `module "web"`); n != 1 {
		t.Errorf("%d calls to web, want the one in the import (the one behind when stays for review):\n%s", n, hcl)
	}
	// The part after the call waits for it.
	if !strings.Contains(hcl, "depends_on = [module.web]") {
		t.Errorf("the part after the call doesn't wait for it:\n%s", hcl)
	}
	if len(res.Review) != 2 {
		t.Fatalf("review: %+v", res.Review)
	}
	// A task in the import notifies the play's handler, which its part has.
	if call := strings.Index(hcl, `module "web"`); !strings.Contains(hcl[:call], "notify = [handler.reload_app]") || !strings.Contains(hcl[:call], `handler "reload_app"`) {
		t.Errorf("the task in the import should notify the play's handler in its own part:\n%s", hcl)
	}
	if r := res.Review[0]; r.File != "more.yml" || r.Line != 5 {
		t.Errorf("the task left in the import is reported at %s line %d, want more.yml line 5: %+v", r.File, r.Line, r)
	}
	if r := res.Review[1]; r.File != "p.yml" || !strings.Contains(r.Reason, "sets when on import_tasks") {
		t.Errorf("the import behind when: %+v", r)
	}
}
