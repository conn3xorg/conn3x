package ansible

import (
	"strings"
	"testing"
)

func TestConvertsApache2Module(t *testing.T) {
	for task, wants := range map[string][]string{
		"community.general.apache2_module: {name: rewrite, state: present}": {`command = "a2enmod -q rewrite"`, `unless  = "test -e /etc/apache2/mods-enabled/rewrite.load"`, "only on Debian and Ubuntu"},
		"apache2_module: {name: status, state: absent}":                     {`command = "a2dismod -q status"`, `unless  = "! test -e /etc/apache2/mods-enabled/status.load"`},
		"apache2_module: {name: mpm_event, state: absent, force: true}":     {`command = "a2dismod -q -f mpm_event"`},
		"apache2_module: {name: php8.3, identifier: php_module}":            {`command = "a2enmod -q php8.3"`},
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

func TestLeavesApache2ModulesItCantGuard(t *testing.T) {
	for reason, task := range map[string]string{
		"ignore_configcheck":   "apache2_module: {name: rewrite, ignore_configcheck: true}",
		"isn't a plain module": "apache2_module: {name: 'rewrite; reboot'}",
		"loops over modules":   "apache2_module: {name: '{{ item }}'}\n      loop: [rewrite, ssl]",
		`state "disabled"`:     "apache2_module: {name: rewrite, state: disabled}",
	} {
		res := convertWithKey(t, "    - "+task+"\n")
		found := false
		for _, r := range res.Review {
			found = found || strings.Contains(r.Reason, reason)
		}
		if res.Converted != 0 || !found {
			t.Errorf("%s: converted %d, review %+v", reason, res.Converted, res.Review)
		}
	}
}
