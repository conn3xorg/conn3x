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

// A role call that sets what the converter can't carry over, such as
// tasks_from or when, is left for review where it was.
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
	if len(res.Review) != 2 || !strings.Contains(res.Review[0].Reason, "sets when on the role") || !strings.Contains(res.Review[1].Reason, "sets tasks_from on include_role") {
		t.Errorf("review: %+v", res.Review)
	}
	if strings.Contains(string(res.HCL), "module ") {
		t.Errorf("wrote a module:\n%s", res.HCL)
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
	// host, base already ran unfiltered never, so it runs.
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
