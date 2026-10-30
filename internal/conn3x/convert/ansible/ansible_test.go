// Copyright (c) The Conn3x Authors
// SPDX-License-Identifier: MPL-2.0

package ansible

import (
	"flag"
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
	if res.Converted != 10 || len(res.Review) != 1 {
		t.Fatalf("converted %d, review %v", res.Converted, res.Review)
	}
	for _, want := range []string{"debug"} {
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
