// Copyright (c) The Conn3x Authors
// SPDX-License-Identifier: MPL-2.0

package ansible

import (
	"strings"
	"testing"
)

// factRepo is a role's deb822_repository task with the name and suite
// given, and extra, such as a when, after them.
func factRepo(name, suite, extra string) map[string]string {
	return map[string]string{"tasks/main.yml": "- name: Repo\n  deb822_repository:\n    name: \"" + name + "\"\n    uris: https://example.com/apt\n    suites: \"" + suite + "\"\n" +
		"    signed_by: |\n      -----BEGIN PGP PUBLIC KEY BLOCK-----\n      abc\n      -----END PGP PUBLIC KEY BLOCK-----\n" + extra}
}

const debianOnly = "  when: ansible_facts.os_family == 'Debian'\n"

// A fact conn3x_host reads with Ansible's spelling becomes the per-host
// lookup, whole or inside text, in each of Ansible's ways to name it.
func TestFactInArgument(t *testing.T) {
	for fact, expr := range map[string]string{
		"distribution_release": "data.conn3x_host.facts[each.key].os_codename",
		"service_mgr":          "data.conn3x_host.facts[each.key].service_manager",
		"architecture":         "data.conn3x_host.facts[each.key].arch",
		"os_family":            `local.os_family[each.key] == "redhat" ? "RedHat" : "Debian"`,
	} {
		for _, spell := range []string{"ansible_facts." + fact, "ansible_facts['" + fact + "']", "ansible_" + fact} {
			res, err := ConvertRole(writeRole(t, factRepo("r-{{ "+spell+" }}", "{{"+spell+"}}", debianOnly)))
			if err != nil {
				t.Fatal(err)
			}
			got := strings.Join(strings.Fields(string(res.Files["main.circuit.hcl"])), " ")
			for _, w := range []string{`name = "r-${` + expr + `}"`, `suites = [` + expr + `]`} {
				if len(res.Review) != 0 || !strings.Contains(got, w) {
					t.Errorf("%s: review %+v, want %s in:\n%s", spell, res.Review, w, got)
				}
			}
		}
	}
	// The data source is declared for a fact read only in an argument.
	res, err := ConvertRole(writeRole(t, map[string]string{"tasks/main.yml": "- copy: {dest: /etc/arch, content: \"{{ ansible_architecture }}\\n\"}\n"}))
	if err != nil {
		t.Fatal(err)
	}
	if out := string(res.Files["main.circuit.hcl"]); len(res.Review) != 0 || !strings.Contains(out, `data "conn3x_host" "facts"`) {
		t.Errorf("review %+v:\n%s", res.Review, out)
	}
}

// A fact stays for review where its value could differ from Ansible's or
// the converter can't check it.
func TestFactInArgumentStays(t *testing.T) {
	for want, files := range map[string]map[string]string{
		"suites uses a Jinja expression":                       factRepo("r", "{{ ansible_facts.distribution_release | upper }}", debianOnly),
		"limit the task to Debian-family hosts":                factRepo("r", "{{ ansible_facts.distribution_release }}", ""),
		"which Ansible spells as a name, such as Ubuntu":       factRepo("r-{{ ansible_facts['distribution'] }}", "noble", debianOnly),
		"with the point release":                               factRepo("r-{{ ansible_distribution_version }}", "noble", debianOnly),
		`reads the host fact "ansible_architecture" in a path`: {"tasks/main.yml": "- copy: {dest: \"/etc/{{ ansible_architecture }}\", content: x}\n"},
		"here it would have to check the value first":          {"tasks/main.yml": "- get_url: {url: \"https://example.com/{{ ansible_architecture }}\", dest: /opt/x, checksum: \"sha256:" + strings.Repeat("a", 64) + "\"}\n"},
	} {
		res, err := ConvertRole(writeRole(t, files))
		if err != nil {
			t.Fatal(err)
		}
		if len(res.Review) != 1 || !strings.Contains(res.Review[0].Reason, want) {
			t.Errorf("want %q, review %+v", want, res.Review)
		}
	}
}
