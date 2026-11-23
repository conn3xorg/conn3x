package ansible

import (
	"strings"
	"testing"
)

// dnf5 is dnf on Fedora 41 and later, so it converts as dnf does.
func TestConvertsDnf5LikeDnf(t *testing.T) {
	for task, want := range map[string]string{
		"ansible.builtin.dnf5: {name: nginx, state: present}": `"nginx"`,
		"dnf5: {name: nginx, install_weak_deps: false}":       "install_recommends = false",
	} {
		res := convertWithKey(t, "    - "+task+"\n")
		if res.Converted != 1 || len(res.Review) != 0 || !strings.Contains(string(res.HCL), want) {
			t.Errorf("%q: converted %d, review %+v, want %q in:\n%s", task, res.Converted, res.Review, want, res.HCL)
		}
	}
	res := convertWithKey(t, "    - dnf5: {name: nginx, enablerepo: epel}\n")
	if res.Converted != 0 || len(res.Review) != 1 || !strings.Contains(res.Review[0].Reason, "enablerepo") {
		t.Errorf("enablerepo: converted %d, review %+v", res.Converted, res.Review)
	}
}
