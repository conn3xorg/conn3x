// Copyright (c) The Conn3x Authors
// SPDX-License-Identifier: MPL-2.0

package ansible

import (
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"

	"github.com/hashicorp/hcl/v2/hclparse"
)

var update = flag.Bool("update", false, "rewrite the golden files")

func TestConvertGolden(t *testing.T) {
	res, err := Convert(filepath.Join("testdata", "web", "site.yml"))
	if err != nil {
		t.Fatal(err)
	}
	golden := filepath.Join("testdata", "web", "site.tf")
	if *update {
		if err := os.WriteFile(golden, res.HCL, 0o644); err != nil {
			t.Fatal(err)
		}
	}
	want, err := os.ReadFile(golden)
	if err != nil {
		t.Fatal(err)
	}
	if string(res.HCL) != string(want) {
		t.Fatalf("output differs from %s (run with -update to accept):\n%s", golden, res.HCL)
	}
	if _, diags := hclparse.NewParser().ParseHCL(res.HCL, "site.tf"); diags.HasErrors() {
		t.Fatalf("output is not valid HCL: %s", diags)
	}
	if res.Converted != 11 || len(res.Review) != 1 {
		t.Fatalf("converted %d, review %v", res.Converted, res.Review)
	}
	for _, want := range []string{"stat"} {
		found := false
		for _, r := range res.Review {
			found = found || strings.Contains(r.Reason, want)
		}
		if !found {
			t.Errorf("no review item mentions %q: %v", want, res.Review)
		}
	}
}

func convertString(t *testing.T, playbook string) Result {
	t.Helper()
	path := filepath.Join(t.TempDir(), "play.yml")
	if err := os.WriteFile(path, []byte(playbook), 0o644); err != nil {
		t.Fatal(err)
	}
	res, err := Convert(path)
	if err != nil {
		t.Fatal(err)
	}
	if _, diags := hclparse.NewParser().ParseHCL(res.HCL, "play.tf"); diags.HasErrors() {
		t.Fatalf("output is not valid HCL: %s\n%s", diags, res.HCL)
	}
	return res
}

// Each of these must be left for a person, never half-translated.
func TestRefusesWhatItCantProve(t *testing.T) {
	for reason, task := range map[string]string{
		"runs on every play":      "command: /usr/local/bin/migrate",
		"no sha256 checksum":      "get_url: {url: 'https://example.com/a', dest: /opt/a}",
		"sets backup_dir":         "copy: {dest: /etc/a, content: x, backup_dir: /tmp}",
		`refers to "port"`:        "lineinfile: {path: /etc/a, line: 'listen {{ port }}'}",
		"Jinja expression":        "copy: {dest: /etc/a, content: \"{{ name | upper }}\"}",
		"uses when":               "package: {name: vim}\n      when: ansible_os_family == 'Debian'",
		"uses register":           "command: {cmd: id, creates: /x}\n      register: out",
		"Jinja template":          "template: {src: a.j2, dest: /etc/a}",
		"appends to the user's":   "user: {name: bob, groups: wheel, append: true}",
		"permanent and immediate": "firewalld: {service: http, permanent: true, state: enabled}",
		"mode on a link":          "file: {src: /opt/a, dest: /usr/local/bin/a, state: link, owner: root}",
		"uses connection":         "command: ./deploy.sh\n      args: {creates: /tmp/done}\n      connection: local",
		"uses remote_user":        "package: {name: vim}\n      remote_user: deploy",
		"uses throttle":           "package: {name: vim}\n      throttle: 1",
		"uses timeout":            "package: {name: vim}\n      timeout: 30",
		"uses become_flags":       "package: {name: vim}\n      become_flags: -H",
		"which is the module":     "package: {name: vim}\n      pip: {name: requests}",
		"force: no":               "copy: {dest: /etc/a, content: x, force: no}",
		"creates is a glob":       "command: {cmd: make, creates: /opt/*.done}",
		"removes is a glob":       "command: {cmd: make clean, removes: '/opt/build[0-9]'}",
		"sets chdir inside":       "command: make chdir=/opt/src\n      args: {creates: /opt/src/out}",
		"create_home: no":         "user: {name: bob, create_home: no}",
	} {
		res := convertString(t, "- hosts: all\n  vars: {name: x}\n  tasks:\n    - "+task+"\n")
		if res.Converted != 0 || len(res.Review) != 1 || !strings.Contains(res.Review[0].Reason, reason) {
			t.Errorf("%q: converted %d, review %+v", task, res.Converted, res.Review)
		}
		if !strings.Contains(string(res.HCL), "TODO(convert)") {
			t.Errorf("%q: no TODO in the output", task)
		}
	}
}

// A cron job moves from the user's crontab to /etc/cron.d, so the old line
// has to go by hand.
func TestCronSaysToRemoveTheOldJob(t *testing.T) {
	res := convertString(t, "- hosts: all\n  tasks:\n    - cron: {name: backup, hour: '2', job: /usr/local/bin/backup}\n")
	if res.Converted != 1 || len(res.Review) != 0 {
		t.Fatalf("converted %d, review %+v", res.Converted, res.Review)
	}
	if want := `TODO(convert): Delete the "#Ansible: backup" job`; !strings.Contains(string(res.HCL), want) {
		t.Errorf("output lacks %q:\n%s", want, res.HCL)
	}
}

func TestHandlerThatIsNotAServiceIsLeft(t *testing.T) {
	res := convertString(t, `- hosts: all
  tasks:
    - copy: {dest: /etc/a, content: x}
      notify: rebuild
  handlers:
    - name: rebuild
      command: make
`)
	if res.Converted != 0 || len(res.Review) != 2 {
		t.Fatalf("converted %d, review %+v", res.Converted, res.Review)
	}
}

func TestConvertsLiteralLoops(t *testing.T) {
	res := convertString(t, `- hosts: all
  tasks:
    - name: Tools
      package:
        name: "{{ item }}"
      loop: [git, jq]
    - name: Config files
      copy:
        dest: "/etc/app/{{ item }}.conf"
        content: "managed\n"
      loop:
        - api
        - worker
`)
	if res.Converted != 2 || len(res.Review) != 0 {
		t.Fatalf("converted %d, review %+v\n%s", res.Converted, res.Review, res.HCL)
	}
	for _, want := range []string{
		`for_each = ["git", "jq"]`,
		`name = item.value`,
		`for_each = ["api", "worker"]`,
		`path    = "/etc/app/${item.value}.conf"`,
	} {
		if !strings.Contains(string(res.HCL), want) {
			t.Errorf("output lacks %q:\n%s", want, res.HCL)
		}
	}
}

// Loops the converter can't prove the same stay for a person.
func TestRefusesOtherLoops(t *testing.T) {
	for reason, task := range map[string]string{
		"loop over a variable": "package: {name: \"{{ item }}\"}\n      loop: \"{{ pkgs }}\"",
		"item.name":            "user: {name: \"{{ item.name }}\"}\n      loop: [{name: a}, {name: b}]",
		"uses when":            "package: {name: \"{{ item }}\"}\n      loop: [a, b]\n      when: x",
		"doesn't use item":     "package: {name: vim}\n      loop: [a, b]",
		"uses loop_control":    "package: {name: \"{{ i }}\"}\n      loop: [a, b]\n      loop_control: {loop_var: i}",
	} {
		res := convertString(t, "- hosts: all\n  vars: {pkgs: x}\n  tasks:\n    - "+task+"\n")
		if res.Converted != 0 || len(res.Review) != 1 || !strings.Contains(res.Review[0].Reason, reason) {
			t.Errorf("%q: converted %d, review %+v", task, res.Converted, res.Review)
		}
	}
}

const armoredKey = "-----BEGIN PGP PUBLIC KEY BLOCK-----\nabc\n-----END PGP PUBLIC KEY BLOCK-----\n"

// convertWithKey converts a playbook with docker.asc in files/ beside it.
func convertWithKey(t *testing.T, tasks string) Result {
	t.Helper()
	dir := t.TempDir()
	if err := os.Mkdir(filepath.Join(dir, "files"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "files", "docker.asc"), []byte(armoredKey), 0o644); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(dir, "play.yml")
	if err := os.WriteFile(path, []byte("- hosts: all\n  tasks:\n"+tasks), 0o644); err != nil {
		t.Fatal(err)
	}
	res, err := Convert(path)
	if err != nil {
		t.Fatal(err)
	}
	if _, diags := hclparse.NewParser().ParseHCL(res.HCL, "play.tf"); diags.HasErrors() {
		t.Fatalf("output is not valid HCL: %s\n%s", diags, res.HCL)
	}
	return res
}

func TestConvertsRepositoriesAndLocale(t *testing.T) {
	const aptRepo = "repo: 'deb [signed-by=/etc/apt/keyrings/docker.asc] https://download.docker.com/linux/ubuntu noble stable'"
	for task, wants := range map[string][]string{
		"ansible.builtin.apt_repository: {" + aptRepo + "}": {
			`name       = "download_docker_com_linux_ubuntu_noble_stable"`,
			`url        = "https://download.docker.com/linux/ubuntu"`,
			`key        = file("${path.module}/files/docker.asc")`,
			`suites     = ["noble"]`,
			`components = ["stable"]`,
			"TODO(convert): Delete the .list file",
		},
		"apt_repository: {repo: 'deb [signed-by=/k/docker.asc] http://example.com/repo ./', update_cache: yes}": {
			`suites = ["./"]`,
		},
		"community.general.apt_repository: {" + aptRepo + "}": {`suites     = ["noble"]`},
		"ansible.builtin.yum_repository: {name: docker-ce, description: Docker, baseurl: 'https://example.com/$releasever/', gpgcheck: true, gpgkey: 'https://example.com/docker.asc'}": {
			`name = "docker-ce"`,
			`url  = "https://example.com/$releasever/"`,
			`key  = file("${path.module}/files/docker.asc")`,
			"description dropped",
		},
		"community.general.yum_repository: {name: d, file: d, enabled: yes, baseurl: [ 'http://example.com/' ], gpgcheck: yes, gpgkey: [ 'file:///etc/pki/docker.asc' ]}": {`name = "d"`},
	} {
		res := convertWithKey(t, "    - "+task+"\n")
		if res.Converted != 1 || len(res.Review) != 0 {
			t.Errorf("%q: converted %d, review %+v", task, res.Converted, res.Review)
		}
		for _, want := range wants {
			if !strings.Contains(string(res.HCL), want) {
				t.Errorf("%q: output lacks %q:\n%s", task, want, res.HCL)
			}
		}
	}
}

func TestRefusesRepositoriesAndLocalesItCantProve(t *testing.T) {
	const keyed = "deb [signed-by=/k/docker.asc] http://example.com/r noble main"
	const yum = "name: d, baseurl: 'http://example.com/', gpgcheck: true, gpgkey: 'http://example.com/docker.asc'"
	for reason, task := range map[string]string{
		`state "absent"`:          "apt_repository: {repo: '" + keyed + "', state: absent}",
		"sets filename":           "apt_repository: {repo: '" + keyed + "', filename: docker}",
		"sets validate_certs":     "apt_repository: {repo: '" + keyed + "', validate_certs: false}",
		"sets mode":               "apt_repository: {repo: '" + keyed + "', mode: '0644'}",
		"update_cache: no":        "apt_repository: {repo: '" + keyed + "', update_cache: no}",
		"isn't a one-line deb":    "apt_repository: {repo: 'ppa:nginx/stable'}",
		"deb-src":                 "apt_repository: {repo: 'deb-src [signed-by=/k/docker.asc] http://example.com/r noble main'}",
		"apt option":              "apt_repository: {repo: 'deb [arch=amd64 signed-by=/k/docker.asc] http://example.com/r noble main'}",
		"doesn't name a key file": "apt_repository: {repo: 'deb http://example.com/r noble main'}",
		"0 components":            "apt_repository: {repo: 'deb [signed-by=/k/docker.asc] http://example.com/r noble'}",
		"1 components":            "apt_repository: {repo: 'deb [signed-by=/k/docker.asc] http://example.com/r ./ main'}",
		"must be an http":         "apt_repository: {repo: 'deb [signed-by=/k/docker.asc] ftp://example.com/r noble main'}",
		"save /k/missing.asc":     "apt_repository: {repo: 'deb [signed-by=/k/missing.asc] http://example.com/r noble main'}",
		"loops over repository":   "apt_repository: {repo: 'deb [signed-by=/k/docker.asc] http://example.com/r {{ item }} main'}\n      loop: [a, b]",
		"exactly one baseurl":     "yum_repository: {name: d, metalink: 'http://example.com/m', gpgcheck: true, gpgkey: 'http://example.com/docker.asc'}",
		"enabled: no":             "yum_repository: {" + yum + ", enabled: no}",
		"gpgcheck: yes":           "yum_repository: {name: d, baseurl: 'http://example.com/', gpgkey: 'http://example.com/docker.asc'}",
		"other than name":         "yum_repository: {" + yum + ", file: other}",
		"exactly one gpgkey":      "yum_repository: {name: d, baseurl: 'http://example.com/', gpgcheck: true}",
		"sets priority":           "yum_repository: {" + yum + ", priority: 10}",
		"may only use letters":    "yum_repository: {name: 'a b', baseurl: 'http://example.com/', gpgcheck: true, gpgkey: 'http://example.com/docker.asc'}",
		"no usable file name":     "yum_repository: {name: d, baseurl: 'http://example.com/', gpgcheck: true, gpgkey: 'http://example.com/a\"b'}",
	} {
		res := convertWithKey(t, "    - "+task+"\n")
		if res.Converted != 0 || len(res.Review) != 1 || !strings.Contains(res.Review[0].Reason, reason) {
			t.Errorf("%q: converted %d, review %+v", task, res.Converted, res.Review)
		}
		if !strings.Contains(string(res.HCL), "TODO(convert)") {
			t.Errorf("%q: no TODO in the output", task)
		}
	}
	// state: absent, written separately as the map keys collide.
	for _, task := range []string{"yum_repository: {" + yum + ", state: absent}"} {
		res := convertWithKey(t, "    - "+task+"\n")
		if res.Converted != 0 || len(res.Review) != 1 || !strings.Contains(res.Review[0].Reason, `state "absent"`) {
			t.Errorf("%q: converted %d, review %+v", task, res.Converted, res.Review)
		}
	}
}

// A locale step sets LANG too, so locale_gen can't convert faithfully.
func TestLocaleGenIsLeft(t *testing.T) {
	for _, task := range []string{"locale_gen: {name: en_GB.UTF-8}", "ansible.builtin.locale_gen: name=fr_FR.UTF-8", "community.general.locale_gen: {name: [en_GB.UTF-8, de_DE.UTF-8]}"} {
		res := convertWithKey(t, "    - "+task+"\n")
		if res.Converted != 0 || len(res.Review) != 1 || !strings.Contains(res.Review[0].Reason, "sets the host's LANG") {
			t.Errorf("%q: converted %d, review %+v", task, res.Converted, res.Review)
		}
	}
}

func TestConvertsIniAndReplace(t *testing.T) {
	for task, wants := range map[string][]string{
		"community.general.ini_file: {path: /etc/a.ini, section: main, option: port, value: '8080'}": {
			"ini {", `path      = "/etc/a.ini"`, `section   = "main"`, `value     = "8080"`, "create    = true", "uncomment = true", "symlink",
		},
		"ini_file: {dest: /etc/a.ini, section: null, option: port, value: 80, create: no, modify_inactive_option: no, follow: yes, no_extra_spaces: yes}": {
			`value           = "80"`, "no_extra_spaces = true",
		},
		"ini_file: {path: /etc/a.ini, section: main, option: port, state: absent}": {`state   = "absent"`},
		"ansible.builtin.replace: {path: /etc/hosts, regexp: 'old\\.example', replace: new.example}": {
			"replace {", `regexp  = "old\\.example"`, `replace = "new.example"`,
		},
		`replace: {dest: /etc/a, regexp: 'a(b+)c', replace: 'x\1y\g<1>\\'}`:               {`replace = "x$${1}y$${1}\\"`},
		`replace: {path: /etc/a, regexp: '(?P<k>[a-z]+)=', replace: '\g<k>: $5 \g<0>\n'}`: {`replace = "$${k}: $$5 $${0}\n"`},
		"replace: {path: /etc/a, regexp: '^#.*$\\n'}":                                     {`replace = ""`},
	} {
		res := convertString(t, "- hosts: all\n  tasks:\n    - "+task+"\n")
		if res.Converted != 1 || len(res.Review) != 0 {
			t.Errorf("%q: converted %d, review %+v", task, res.Converted, res.Review)
		}
		for _, want := range wants {
			if !strings.Contains(string(res.HCL), want) {
				t.Errorf("%q: output lacks %q:\n%s", task, want, res.HCL)
			}
		}
	}
}

func TestRefusesIniAndReplaceItCantProve(t *testing.T) {
	const ini, rep = "ini_file: {path: /a, section: s, option: o, value: 'v', ", "replace: {path: /a, replace: 'x', regexp: "
	for task, reason := range map[string]string{
		"ini_file: path=/a section=s option=o value='a b'":                           "key=value text",
		"replace: path=/a regexp='a b' replace=c":                                    "key=value text",
		"ini_file: {path: /a, section: s}":                                           "whole section",
		"ini_file: {path: /a, section: s, option: o}":                                "no value",
		"ini_file: {path: /a, section: s, option: o, value: v, state: absent}":       "whatever its value",
		"ini_file: {path: /a, section: s, option: o, state: absent, create: no}":     "create: no",
		"ini_file: {path: /a, section: '', option: o, value: v}":                     "empty section",
		"ini_file: {path: /a, section: s, option: o, value: yes}":                    "may read",
		"ini_file: {path: /a, section: s, option: o, value: 1.10}":                   "may read",
		"ini_file: {path: /a, section: s, option: o, value: 0644}":                   "may read",
		"ini_file: {path: /a, section: s, option: o, value: \"{{ b }}\"}":            "may read",
		ini + "exclusive: no}":                                                       "exclusive",
		ini + "allow_no_value: yes}":                                                 "allow_no_value",
		ini + "ignore_spaces: yes}":                                                  "ignore_spaces",
		ini + "backup: yes}":                                                         "backup",
		ini + "mode: '0600'}":                                                        "sets mode",
		ini + "owner: root}":                                                         "sets owner",
		ini + "section_has_values: []}":                                              "section_has_values",
		ini + "values: [a, b]}":                                                      "sets values",
		"ini_file: {path: /a, section: s, option: 'a=b', value: v}":                  "can't be an ini step",
		"ini_file: {path: /a, section: s, option: o, value: '{# c #}'}":              "Jinja comment",
		"ini_file: {path: /a, option: o, value: \"{{ item }}\"}\n      loop: [a, b]": "loops",
		"replace: {path: /a, replace: x}":                                            "no regexp",
		"replace: {path: /a, regexp: 1.5, replace: x}":                               "may read",
		"replace: {path: /a, regexp: a, replace: yes}":                               "may read",
		rep + "a, after: b}":                                                         "sets after",
		rep + "a, before: b}":                                                        "sets before",
		rep + "a, backup: yes}":                                                      "backup",
		rep + "a, encoding: latin-1}":                                                "encoding",
		rep + "a, validate: 'x %s'}":                                                 "sets validate",
		rep + "a, mode: '0600'}":                                                     "sets mode",
		// Python and Go read these differently, or Go can't read them.
		rep + "'a(?=b)'}":      "lookaround",
		rep + "'a(?!b)'}":      "lookaround",
		rep + "'(?<=a)b'}":     "lookaround",
		rep + "'(?<!a)b'}":     "lookaround",
		rep + "'(?i)a'}":       "flag",
		rep + "'(?s)a.b'}":     "flag",
		rep + "'(?x) a'}":      "flag",
		rep + "'(?#c)a'}":      "flag",
		rep + "'(?P=n)a'}":     "flag",
		rep + "'(a)\\1'}":      "\\1",
		rep + "'\\d+'}":        "\\d",
		rep + "'\\w+'}":        "\\w",
		rep + "'a\\s'}":        "\\s",
		rep + "'\\ba'}":        "\\b",
		rep + "'a\\Z'}":        "\\Z",
		rep + "'\\x41'}":       "\\x",
		rep + "'\\pL'}":        "\\p",
		rep + "'[\\d]a'}":      "\\d",
		rep + "'[[:alpha:]]'}": "[:",
		rep + "'a{,3}b'}":      "{,n}",
		rep + "'a*+b'}":        "can't compile",
		rep + "'(a'}":          "can't compile",
		rep + "'a{2000}'}":     "can't compile",
		rep + "'x*'}":          "match nothing",
		rep + "'^'}":           "match nothing",
		rep + "'^.*$'}":        "match nothing",
		rep + "'a|'}":          "match nothing",
		rep + "'(a*)+b'}":      "repeat of something",
		// Replacements.
		"replace: {path: /a, regexp: '(a)', replace: '\\2'}":                          "group 2",
		"replace: {path: /a, regexp: '(a)', replace: '\\g<k>'}":                       "group k",
		"replace: {path: /a, regexp: 'a', replace: '\\1'}":                            "group 1",
		"replace: {path: /a, regexp: '(a)', replace: '\\12'}":                         "\\1",
		"replace: {path: /a, regexp: '(a)', replace: '\\0'}":                          "\\0",
		"replace: {path: /a, regexp: '(a)', replace: '\\q'}":                          "\\q",
		"replace: {path: /a, regexp: '(a)', replace: 'b\\'}":                          "lone",
		"replace: {path: /a, regexp: '(a)', replace: '\\g<1'}":                        "\\g",
		"replace: {path: /a, regexp: 'foo', replace: 'foofoo'}":                       "never settles",
		"replace: {path: /a, regexp: 'foo', replace: 'foo bar'}":                      "never settles",
		"replace: {path: /a, regexp: 'a', replace: '{# c #}'}":                        "Jinja comment",
		"replace: {path: /a, regexp: \"{{ item }}\", replace: x}\n      loop: [a, b]": "loops",
	} {
		res := convertString(t, "- hosts: all\n  vars: {b: yes}\n  tasks:\n    - "+task+"\n")
		if res.Converted != 0 || len(res.Review) != 1 || !strings.Contains(res.Review[0].Reason, reason) {
			t.Errorf("%q: converted %d, review %+v", task, res.Converted, res.Review)
		}
		if !strings.Contains(string(res.HCL), "TODO(convert)") {
			t.Errorf("%q: no TODO in the output", task)
		}
	}
}

// Expected results are Python's: what ansible.builtin.replace's regexp does.
// Go has to give the same for every pattern the converter lets through.
func TestProvenRegexpsMatchPython(t *testing.T) {
	for _, tc := range []struct{ pattern, py, in, want string }{
		{`^a=.*$`, `a=0`, "a=1\nb=2\na=3\n", "a=0\nb=2\na=0\n"},
		{`b+?`, `X`, "abbbc", "aXXXc"},
		{`a|ab`, `X`, "ab abc", "Xb Xbc"},
		{`(a|ab)(c|bcd)`, `[\1|\2]`, "abcd", "[a|bcd]"},
		{`(a)|(b)`, `<\1\2>`, "ab", "<a><b>"},
		{`(?:a|b)+c`, `X`, "abac", "X"},
		{`(a|b)+c`, `\1`, "abac", "a"},
		{`[^#\n]+$`, `X`, "ab#cd\nef\n", "ab#X\nX\n"},
		{`[^#]x`, `Y`, "a\nx#x\n", "aY#x\n"},
		{`\Aa`, `X`, "a\na\n", "X\na\n"},
		{`a$`, `X`, "a\r\na\n", "a\r\nX\n"},
		{`a\nb`, `c`, "a\nb\n", "c\n"},
		{`é.`, `\g<0>!`, "éa ñ", "éa! ñ"},
		{`.`, `x`, "é\n", "x\n"},
		{`a{2}`, `X`, "aaaaa", "XXa"},
		{`a{2,}`, `X`, "aaaaa b aa", "X b X"},
		{`a{x}`, `X`, "a{x}", "X"},
		{`[]a]+`, `X`, "]a]b", "Xb"},
		{`[a\-c]`, `X`, "a-bc", "XXbX"},
		{`\.\*\$`, `$1`, ".*$", "$1"},
		{`(?P<k>[a-z]+)=(?P<v>[0-9]+)`, `\g<v>=\g<k>`, "ab=12", "12=ab"},
		{`x`, `a\tb\nc\\d`, "x", "a\tb\nc\\d"},
		{`(x)`, `\1\g<1>1`, "x", "xx1"},
	} {
		if why := unprovableRegexp(tc.pattern); why != "" {
			t.Errorf("%q refused: %s", tc.pattern, why)
			continue
		}
		tmpl, why := goTemplate(tc.py, regexp.MustCompile(tc.pattern))
		if why != "" {
			t.Errorf("%q: %s", tc.py, why)
			continue
		}
		if got := regexp.MustCompile("(?m)"+tc.pattern).ReplaceAllString(tc.in, tmpl); got != tc.want {
			t.Errorf("%q -> %q on %q: got %q, want %q", tc.pattern, tc.py, tc.in, got, tc.want)
		}
	}
}

// A secret under no_log must not reach the .tf file: not as a step, and not in
// the comment that keeps a task for review.
func TestNoLogIsLeftForReview(t *testing.T) {
	task := func(noLog string) string {
		return "  tasks:\n    - name: secret\n      no_log: " + noLog + "\n      copy:\n        dest: /etc/app.key\n        content: hunter2\n"
	}
	const plain = "    - name: secret\n      copy:\n        dest: /etc/app.key\n        content: hunter2\n"
	const play = "- hosts: web\n"
	for name, tc := range map[string]struct {
		playbook string
		reason   bool // the reason is no_log, rather than another one
	}{
		"true":             {play + task("true"), true},
		"yes":              {play + task("yes"), true},
		"quoted true":      {play + task(`"true"`), true},
		"one":              {play + task("1"), true},
		"templated":        {play + task(`"{{ hide }}"`), true},
		"templated false":  {play + task(`"{{ false }}"`), true},
		"empty":            {play + task(""), true},
		"a list":           {play + task("[false]"), true},
		"alias":            {"- hosts: web\n  vars:\n    x: &on true\n" + task("*on"), true},
		"merge":            {"- hosts: web\n  vars:\n    d: &d\n      no_log: true\n  tasks:\n    - name: secret\n      <<: *d\n      copy:\n        dest: /etc/app.key\n        content: hunter2\n", true},
		"before a loop":    {play + "  tasks:\n    - name: secret\n      no_log: true\n      with_items: [hunter2]\n      debug:\n        msg: x\n", true},
		"play":             {play + "  no_log: true\n  tasks:\n" + plain, true},
		"play templated":   {play + "  no_log: \"{{ hide }}\"\n  tasks:\n" + plain, true},
		"play pre_tasks":   {play + "  no_log: true\n  pre_tasks:\n" + plain, true},
		"play merge":       {"- &p\n  hosts: other\n  no_log: true\n- <<: *p\n  hosts: web\n  tasks:\n" + plain, true},
		"block":            {play + "  tasks:\n    - no_log: true\n      block:\n" + "    " + strings.ReplaceAll(plain, "\n    ", "\n        "), true},
		"inside a block":   {play + "  tasks:\n    - block:\n        - name: secret\n          no_log: true\n          copy:\n            dest: /etc/app.key\n            content: hunter2\n", true},
		"inside rescue":    {play + "  tasks:\n    - block:\n        - debug:\n            msg: x\n      rescue:\n        - name: secret\n          no_log: true\n          copy:\n            content: hunter2\n", true},
		"handler":          {play + "  handlers:\n    - name: secret\n      no_log: true\n      service:\n        name: hunter2\n        state: restarted\n", true},
		"play and handler": {play + "  no_log: true\n  handlers:\n    - name: secret\n      service:\n        name: hunter2\n        state: restarted\n", true},
		"role":             {play + "  roles:\n    - role: app\n      no_log: true\n      password: hunter2\n", false},
		"play and role":    {play + "  no_log: true\n  roles:\n    - role: app\n      password: hunter2\n", false},
	} {
		t.Run(name, func(t *testing.T) {
			res := convertString(t, tc.playbook)
			if strings.Contains(string(res.HCL), "hunter2") {
				t.Fatalf("the secret reached the file:\n%s", res.HCL)
			}
			if res.Converted != 0 || len(res.Review) != 1 {
				t.Fatalf("converted %d, review %v", res.Converted, res.Review)
			}
			if tc.reason && !strings.Contains(res.Review[0].Reason, "write them to this file") {
				t.Fatalf("reason: %q", res.Review[0].Reason)
			}
			if !strings.Contains(string(res.HCL), "TODO(convert)") {
				t.Fatalf("no TODO:\n%s", res.HCL)
			}
			if _, diags := hclparse.NewParser().ParseHCL(res.HCL, "play.tf"); diags.HasErrors() {
				t.Fatalf("output is not valid HCL: %s\n%s", diags, res.HCL)
			}
		})
	}
}

// no_log false hides nothing, and the task's own setting beats its play's.
func TestNoLogFalseStillConverts(t *testing.T) {
	task := func(noLog string) string {
		return "  tasks:\n    - name: open\n      no_log: " + noLog + "\n      copy:\n        dest: /etc/app.conf\n        content: fine\n"
	}
	for name, playbook := range map[string]string{
		"false":         "- hosts: web\n" + task("false"),
		"False":         "- hosts: web\n" + task("False"),
		"no":            "- hosts: web\n" + task("no"),
		"quoted":        "- hosts: web\n" + task(`"false"`),
		"over its play": "- hosts: web\n  no_log: true\n" + task("false"),
		"play false":    "- hosts: web\n  no_log: false\n  tasks:\n    - name: open\n      copy:\n        dest: /etc/app.conf\n        content: fine\n",
	} {
		t.Run(name, func(t *testing.T) {
			res := convertString(t, playbook)
			if res.Converted != 1 || len(res.Review) != 0 {
				t.Fatalf("converted %d, review %v", res.Converted, res.Review)
			}
		})
	}
}

// One play's no_log doesn't reach the next.
func TestNoLogStaysInItsPlay(t *testing.T) {
	res := convertString(t, "- hosts: a\n  no_log: true\n  tasks:\n    - name: secret\n      copy:\n        dest: /a\n        content: hunter2\n- hosts: b\n  tasks:\n    - name: open\n      copy:\n        dest: /b\n        content: fine\n")
	if res.Converted != 1 || len(res.Review) != 1 || strings.Contains(string(res.HCL), "hunter2") {
		t.Fatalf("converted %d, review %v:\n%s", res.Converted, res.Review, res.HCL)
	}
}

const (
	hostKeyA = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIOMqqnkVzrm0SdG6UOoqKLsabgH5C9okWi0dh2l9GKJl"
	hostLine = "gh.example " + hostKeyA
)

func TestConvertsKnownHosts(t *testing.T) {
	for name, c := range map[string]struct {
		play  string
		task  string
		wants []string
	}{
		"system file":   {"", "ansible.builtin.known_hosts: {name: gh.example, key: '" + hostLine + "', path: /etc/ssh/ssh_known_hosts}", []string{"known_hosts {", `host = "gh.example"`, `key  = "` + hostKeyA + `"`, "symlink"}},
		"host alias":    {"", "known_hosts: {host: gh.example, key: '" + hostLine + "', path: /etc/ssh/ssh_known_hosts}", []string{`host = "gh.example"`}},
		"keeps comment": {"", "known_hosts: {name: gh.example, key: '" + hostLine + " note', path: /etc/ssh/ssh_known_hosts, hash_host: no}", []string{hostKeyA + " note"}},
		"custom port":   {"", "known_hosts: {name: '[gh.example]:2222', key: '[gh.example]:2222 " + hostKeyA + "', path: /etc/ssh/ssh_known_hosts}", []string{`host = "[gh.example]:2222"`}},
		"absent":        {"", "known_hosts: {name: gh.example, state: absent, path: /etc/ssh/ssh_known_hosts}", []string{`state = "absent"`}},
		"become user":   {"  become: true\n", "known_hosts: {name: gh.example, key: '" + hostLine + "'}", []string{`user = "root"`, "~/.ssh is missing"}},
		"login user":    {"", "known_hosts: {name: gh.example, key: '" + hostLine + "', path: ~/.ssh/known_hosts}", []string{"user = var.ssh_user"}},
	} {
		res := convertString(t, "- hosts: all\n"+c.play+"  tasks:\n    - "+c.task+"\n")
		if res.Converted != 1 || len(res.Review) != 0 {
			t.Errorf("%s: converted %d, review %+v", name, res.Converted, res.Review)
		}
		for _, want := range c.wants {
			if !strings.Contains(string(res.HCL), want) {
				t.Errorf("%s: output lacks %q:\n%s", name, want, res.HCL)
			}
		}
	}
}

func TestRefusesKnownHostsItCantProve(t *testing.T) {
	const sys = ", path: /etc/ssh/ssh_known_hosts}"
	line := "key: '" + hostLine + "'"
	for task, reason := range map[string]string{
		"known_hosts: name=gh.example path=/etc/ssh/ssh_known_hosts":                        "key=value text",
		"known_hosts: {name: gh.example, " + line + ", path: /home/a/.ssh/known_hosts}":     "may have acted on this path as root",
		"known_hosts: {name: gh.example, " + line + ", path: ~deploy/.ssh/known_hosts}":     "may have acted on this path as root",
		"known_hosts: {name: GH.example, key: 'GH.example " + hostKeyA + "'" + sys:          "capitals",
		"known_hosts: {name: gh.example, " + line + ", hash_host: yes" + sys:                "hash_host",
		"known_hosts: {name: gh.example, key: 'gh.example,1.2.3.4 " + hostKeyA + "'" + sys:  "doesn't start with exactly its name",
		"known_hosts: {name: gh.example, key: '|1|a|b " + hostKeyA + "'" + sys:              "doesn't start with exactly its name",
		"known_hosts: {name: gh.example, key: '@revoked gh.example " + hostKeyA + "'" + sys: "doesn't start with exactly its name",
		"known_hosts: {name: gh.example, key: 'other.example " + hostKeyA + "'" + sys:       "doesn't start with exactly its name",
		"known_hosts: {name: gh.example, key: 'gh.example nonsense'" + sys:                  "can't be a known_hosts step",
		"known_hosts: {name: gh.example, " + line + ", state: absent" + sys:                 "takes no key",
		"known_hosts: {name: 'gh*', state: absent" + sys:                                    "can't be a known_hosts step",
		"known_hosts: {name: gh.example, state: latest" + sys:                               "state",
		"known_hosts: {name: gh.example, " + line + ", mode: '0600'" + sys:                  "sets mode",
		"known_hosts: {name: \"{{ h }}\", key: \"{{ k }}\"" + sys:                           "refers to",
		"known_hosts: {name: \"{{ item }}\", " + line + sys + "\n      loop: [a, b]":        "loops",
		"known_hosts: {name: gh.example, " + line + sys + "\n      when: x":                 "uses when",
	} {
		res := convertString(t, "- hosts: all\n  tasks:\n    - "+task+"\n")
		if res.Converted != 0 || len(res.Review) != 1 || !strings.Contains(res.Review[0].Reason, reason) {
			t.Errorf("%q: converted %d, review %+v, want %q", task, res.Converted, res.Review, reason)
		}
	}
	// Anything that can change who runs the task leaves the default path open.
	for _, play := range []string{"  become: true\n  become_user: deploy\n", "  vars_files: [v.yml]\n", "  remote_user: deploy\n", "  vars: {ansible_user: deploy}\n", "  vars: {ansible_become: true}\n"} {
		res := convertString(t, "- hosts: all\n"+play+"  tasks:\n    - known_hosts: {name: gh.example, "+line+"}\n")
		if res.Converted != 0 || !strings.Contains(fmt.Sprint(res.Review), "leaves that open") {
			t.Errorf("%q: converted %d, review %+v", play, res.Converted, res.Review)
		}
	}
	// The task-level forms stop at the keyword check.
	res := convertString(t, "- hosts: all\n  tasks:\n    - known_hosts: {name: gh.example, "+line+"}\n      become_user: deploy\n")
	if res.Converted != 0 || !strings.Contains(fmt.Sprint(res.Review), "become_user") {
		t.Errorf("task become_user: %+v", res.Review)
	}
}

func TestKnownHostsDefaultPathWatchesFilesBesideThePlaybook(t *testing.T) {
	for _, name := range []string{"ansible.cfg", "group_vars"} {
		dir := t.TempDir()
		if err := os.WriteFile(filepath.Join(dir, name), nil, 0o644); err != nil {
			t.Fatal(err)
		}
		play := filepath.Join(dir, "play.yml")
		if err := os.WriteFile(play, []byte("- hosts: all\n  tasks:\n    - known_hosts: {name: gh.example, key: '"+hostLine+"'}\n"), 0o644); err != nil {
			t.Fatal(err)
		}
		res, err := Convert(play)
		if err != nil || res.Converted != 0 {
			t.Errorf("%s beside the playbook: converted %d, %v", name, res.Converted, err)
		}
	}
}

func TestConvertsPamLimits(t *testing.T) {
	res := convertString(t, "- hosts: all\n  tasks:\n    - community.general.pam_limits: {domain: joe, limit_type: soft, limit_item: nofile, value: 64000}\n    - pam_limits: {dest: /etc/security/limits.d/a.conf, domain: '*', limit_type: '-', limit_item: core, value: unlimited, backup: no, use_max: no, comment: ''}\n    - pam_limits: {domain: '@g', limit_type: hard, limit_item: nice, value: -5}\n")
	if res.Converted != 3 || len(res.Review) != 0 {
		t.Fatalf("converted %d, review %+v", res.Converted, res.Review)
	}
	for _, want := range []string{"limit {", `path   = "/etc/security/limits.conf"`, `domain = "joe"`, `value  = "64000"`, `path   = "/etc/security/limits.d/a.conf"`, `type   = "-"`, `value  = "unlimited"`, `value  = "-5"`, "create = true", "symlink"} {
		if !strings.Contains(string(res.HCL), want) {
			t.Errorf("output lacks %q:\n%s", want, res.HCL)
		}
	}
}

func TestRefusesPamLimitsItCantProve(t *testing.T) {
	const base = "pam_limits: {domain: j, limit_type: soft, limit_item: nofile, "
	for task, reason := range map[string]string{
		"pam_limits: domain=j limit_type=soft limit_item=nofile value=1":          "key=value text",
		base + "value: 1, use_max: yes}":                                          "use_max",
		base + "value: 1, use_min: yes}":                                          "use_min",
		base + "value: 1, backup: yes}":                                           "backup",
		base + "value: 1, comment: why}":                                          "comment",
		base + "value: 1, mode: '0600'}":                                          "sets mode",
		base + "value: 010}":                                                      "may read",
		base + "value: 1.5}":                                                      "may read",
		base + "value: lots}":                                                     "can't be a limit step",
		base + "value: \"{{ n }}\"}":                                              "refers to",
		"pam_limits: {domain: j, limit_type: both, limit_item: nofile, value: 1}": "can't be a limit step",
		"pam_limits: {domain: j, limit_type: soft, limit_item: bogus, value: 1}":  "can't be a limit step",
	} {
		res := convertString(t, "- hosts: all\n  tasks:\n    - "+task+"\n")
		if res.Converted != 0 || len(res.Review) != 1 || !strings.Contains(res.Review[0].Reason, reason) {
			t.Errorf("%q: converted %d, review %+v, want %q", task, res.Converted, res.Review, reason)
		}
	}
}

func TestDebugIsDroppedWithoutItsMessage(t *testing.T) {
	const secret = "hunter2"
	for task, want := range map[string]string{
		"debug: {msg: 'password is " + secret + "'}":                 "isn't copied",
		"ansible.builtin.debug: {msg: 'password is " + secret + "'}": "isn't copied",
		"debug: msg='" + secret + "'":                                "isn't copied",
		"debug: {msg: \"" + secret + " {{ x }}\"}":                   "templated",
		"debug: {msg: ['" + secret + "']}":                           "templated",
		"debug: {var: db_password}":                                  "variable db_password",
		"debug: {var: \"lookup('file', '/" + secret + "')\"}":        "an expression",
		"debug: {msg: '" + secret + "', verbosity: 2}":               "isn't copied",
		"debug:": "left out",
	} {
		res := convertString(t, "- hosts: all\n  tasks:\n    - "+task+"\n")
		if res.Converted != 1 || len(res.Review) != 0 {
			t.Errorf("%q: converted %d, review %+v", task, res.Converted, res.Review)
		}
		out := string(res.HCL)
		if !strings.Contains(out, want) || strings.Contains(out, "step ") {
			t.Errorf("%q: output lacks %q or has a step:\n%s", task, want, out)
		}
		if strings.Contains(out, secret) {
			t.Errorf("%q: copied the message:\n%s", task, out)
		}
		if _, diags := hclparse.NewParser().ParseHCL(res.HCL, "x.tf"); diags.HasErrors() {
			t.Errorf("%q: %s", task, diags)
		}
	}
}

// A debug task that stays for review still mustn't copy what it prints, in any
// form that reaches the comment that holds a reviewed task.
func TestDebugLeftForReviewDoesntCopyItsMessage(t *testing.T) {
	const secret = "hunter2"
	msg := "msg: '" + secret + "'"
	for task, reason := range map[string]string{
		"debug: {" + msg + "}\n      when: x":               "uses when",
		"debug: {" + msg + "}\n      register: r":           "uses register",
		"debug: {" + msg + "}\n      failed_when: true":     "uses failed_when",
		"debug: {" + msg + "}\n      loop: [a, b]":          "doesn't use item",
		"debug: {" + msg + ", var: x}":                      "both msg and var",
		"debug: {" + msg + ", bogus: 1}":                    "sets bogus",
		"action: debug msg=" + secret:                       "uses action",
		"action: {module: debug, " + msg + "}":              "uses action",
		"local_action: ansible.builtin.debug msg=" + secret: "uses local_action",
		"block:\n        - debug: {" + msg + "}":            "uses block",
	} {
		res := convertString(t, "- hosts: all\n  tasks:\n    - "+task+"\n")
		if res.Converted != 0 || len(res.Review) != 1 || !strings.Contains(res.Review[0].Reason, reason) {
			t.Errorf("%q: converted %d, review %+v, want %q", task, res.Converted, res.Review, reason)
		}
		if strings.Contains(string(res.HCL), secret) {
			t.Errorf("%q: copied the message:\n%s", task, res.HCL)
		}
	}
	res := convertString(t, "- hosts: all\n  handlers:\n    - name: h\n      debug: {"+msg+"}\n  tasks: []\n")
	if strings.Contains(string(res.HCL), secret) {
		t.Errorf("handler copied the message:\n%s", res.HCL)
	}
}

func TestNoLogStillRefusesTheseModules(t *testing.T) {
	const secret = "hunter2"
	for _, task := range []string{"debug: {msg: " + secret + "}", "known_hosts: {name: " + secret + ", key: '" + secret + "', path: /etc/ssh/ssh_known_hosts}", "pam_limits: {domain: " + secret + ", limit_type: soft, limit_item: core, value: 1}"} {
		for _, playbook := range []string{
			"- hosts: all\n  tasks:\n    - " + task + "\n      no_log: true\n",
			"- hosts: all\n  no_log: true\n  tasks:\n    - " + task + "\n",
		} {
			res := convertString(t, playbook)
			if res.Converted != 0 || len(res.Review) != 1 || !strings.Contains(res.Review[0].Reason, "no_log") {
				t.Errorf("%q: converted %d, review %+v", playbook, res.Converted, res.Review)
			}
			if strings.Contains(string(res.HCL), secret) {
				t.Errorf("%q: copied a value:\n%s", playbook, res.HCL)
			}
		}
	}
}

<<<<<<< Updated upstream
func TestPlayThatChangesTheUserSendsUserDependentTasksToReview(t *testing.T) {
	const tasks = `  tasks:
    - copy: {dest: /a, content: x}
    - file: {path: /b, state: directory}
    - lineinfile: {path: /c, line: x}
    - command: {cmd: "true", creates: /d}
    - cron: {name: j, job: "true"}
    - wait_for: {path: /e}
    - package: {name: tree}
    - cron: {name: k, job: "true", user: app}
    - wait_for: {port: 22}
`
	for _, play := range []string{
		"become: true\n  become_user: postgres",
		"become_user: postgres", // become can be on in ansible.cfg
		"become: '{{ b }}'\n  become_user: postgres",
		"remote_user: deploy",
		"become: false\n  remote_user: deploy",
		"vars: {ansible_become_user: postgres}",
		"vars: {ansible_become: true}",
		"vars: {ansible_user: deploy}",
	} {
		res := convertString(t, "- hosts: all\n  "+play+"\n"+tasks)
		if res.Converted != 3 || len(res.Review) != 6 {
			t.Errorf("%q: converted %d, review %+v", play, res.Converted, res.Review)
			continue
		}
		if r := res.Review[0].Reason; !strings.Contains(r, "depends on which user runs it") {
			t.Errorf("%q: reason %q", play, r)
		}
	}
}

func TestPlayThatKeepsTheUserConverts(t *testing.T) {
	for _, play := range []string{
		"become: true",
		"become: true\n  become_user: root",
		"become: true\n  remote_user: deploy", // only picks who logs in
		"become: false\n  become_user: postgres",
		"become_user: root",
	} {
		res := convertString(t, "- hosts: all\n  "+play+"\n  tasks:\n    - copy: {dest: /a, content: x}\n")
		if res.Converted != 1 || len(res.Review) != 0 {
			t.Errorf("%q: converted %d, review %+v", play, res.Converted, res.Review)
		}
	}
}

// The module's own reason comes first, and sits beside the tasks it stopped.
func TestChangedUserDoesNotHideAModulesOwnReason(t *testing.T) {
	res := convertString(t, "- hosts: all\n  remote_user: deploy\n  tasks:\n    - command: 'true'\n")
	if len(res.Review) != 1 || !strings.Contains(res.Review[0].Reason, "runs on every play") {
		t.Fatalf("review %+v", res.Review)
=======
func TestConvertsPip(t *testing.T) {
	res := convertString(t, `- hosts: all
  become: true
  tasks:
    - ansible.builtin.pip: {name: six, version: "1.16.0", virtualenv: /opt/v}
    - pip: {name: ["iniconfig==2.0.0", tomli], virtualenv: /opt/v, virtualenv_command: python3 -m venv}
    - pip: {name: packaging, state: latest, virtualenv: /opt/v, virtualenv_command: virtualenv}
    - pip: {name: old, state: absent, virtualenv: /opt/v, editable: false, virtualenv_site_packages: false}
`)
	if res.Converted != 4 || len(res.Review) != 0 {
		t.Fatalf("converted %d, review %+v", res.Converted, res.Review)
	}
	for _, want := range []string{"pip {", `name = "six"`, `version = "1.16.0"`, `version = "2.0.0"`, `name = "tomli"`, `state = "latest"`, `state = "absent"`, "virtualenv tool"} {
		if !strings.Contains(strings.Join(strings.Fields(string(res.HCL)), " "), want) {
			t.Errorf("output lacks %q:\n%s", want, res.HCL)
		}
	}
}

func TestRefusesPipItCantProve(t *testing.T) {
	for _, c := range []struct{ task, want string }{
		{"pip: {name: six}", "outside a virtualenv"},
		{"pip: {requirements: /opt/r.txt, virtualenv: /opt/v}", "requirements file"},
		{"pip: {name: six, virtualenv: ~/v}", "clean absolute path"},
		{"pip: {name: six, virtualenv: v}", "clean absolute path"},
		{"pip: {name: six, virtualenv: /home/a/v}", "home directory"},
		{"pip: {name: six, virtualenv: /root/v}", "home directory"},
		{`pip: {name: "six>=1", virtualenv: /opt/v}`, "plain name"},
		{`pip: {name: "six[x]==1", virtualenv: /opt/v}`, "plain name"},
		{"pip: {name: git+https://x.example/y, virtualenv: /opt/v}", "plain name"},
		{`pip: {name: "six==1.*", virtualenv: /opt/v}`, "exact version"},
		{`pip: {name: "six==1", version: "1", virtualenv: /opt/v}`, "also sets version"},
		{`pip: {name: [a, b], version: "1", virtualenv: /opt/v}`, "several names"},
		{"pip: {name: six, version: 1.10, virtualenv: /opt/v}", "may read as"},
		{`pip: {name: six, version: "1", state: latest, virtualenv: /opt/v}`, "only applies"},
		{`pip: {name: six, version: "1", state: absent, virtualenv: /opt/v}`, "only applies"},
		{"pip: {name: six, state: forcereinstall, virtualenv: /opt/v}", "no Conn3x equivalent"},
		{"pip: {name: six, extra_args: --index-url=http://x, virtualenv: /opt/v}", "extra_args"},
		{"pip: {name: six, executable: /opt/v/bin/pip3, virtualenv: /opt/v}", "executable"},
		{"pip: {name: six, chdir: /tmp, virtualenv: /opt/v}", "chdir"},
		{"pip: {name: six, umask: '0022', virtualenv: /opt/v}", "umask"},
		{"pip: {name: six, virtualenv_python: python3.12, virtualenv: /opt/v}", "virtualenv_python"},
		{"pip: {name: six, virtualenv_command: pyvenv, virtualenv: /opt/v}", "builds its virtualenv"},
		{"pip: {name: six, virtualenv_site_packages: true, virtualenv: /opt/v}", "site_packages"},
		{"pip: {name: six, editable: true, virtualenv: /opt/v}", "editable"},
		{"pip: name=six virtualenv=/opt/v", "key=value"},
		{"pip: {name: '{{ item }}', virtualenv: /opt/v}\n      loop: [a]", "loops"},
		{"pip: {name: '{{ pkg }}', virtualenv: /opt/v}", "play variable"},
		{"pip: {virtualenv: /opt/v}", "names no package"},
	} {
		res := convertString(t, "- hosts: all\n  become: true\n  tasks:\n    - "+c.task+"\n")
		if res.Converted != 0 || len(res.Review) != 1 || !strings.Contains(res.Review[0].Reason, c.want) {
			t.Errorf("%s: converted %d, review %+v, want %q", c.task, res.Converted, res.Review, c.want)
		}
	}
	res := convertString(t, "- hosts: all\n  tasks:\n    - pip: {name: six, virtualenv: /opt/v, password: s3cret}\n      no_log: true\n")
	if res.Converted != 0 || strings.Contains(string(res.HCL), "s3cret") {
		t.Errorf("no_log task: %s", res.HCL)
	}
}

// Who runs pip decides who owns the venv and whose code it trusts.
func TestPipGoesToReviewWhenThePlayChangesTheUser(t *testing.T) {
	res := convertString(t, "- hosts: all\n  become: true\n  become_user: app\n  tasks:\n    - pip: {name: six, virtualenv: /opt/v}\n")
	if res.Converted != 0 || len(res.Review) != 1 || !strings.Contains(res.Review[0].Reason, "become_user") {
		t.Fatalf("converted %d, review %+v", res.Converted, res.Review)
>>>>>>> Stashed changes
	}
}
