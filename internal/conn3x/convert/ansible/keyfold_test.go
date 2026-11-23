package ansible

import (
	"strings"
	"testing"
)

func TestFoldsKeyTaskIntoRepository(t *testing.T) {
	for name, c := range map[string]struct {
		tasks string
		wants []string
	}{
		"apt_key then apt_repository": {
			"    - ansible.builtin.apt_key: {url: 'https://example.com/docker.asc', state: present}\n" +
				"    - apt_repository: {repo: 'deb https://example.com/r noble main'}\n",
			[]string{`key        = file("${path.module}/files/docker.asc")`, "imports https://example.com/docker.asc, which the repository step after it takes"},
		},
		"rpm_key then yum_repository": {
			"    - rpm_key: {key: 'https://example.com/docker.asc'}\n" +
				"    - yum_repository: {name: d, baseurl: 'https://example.com/', gpgcheck: true, gpgkey: 'https://example.com/docker.asc'}\n",
			[]string{`key  = file("${path.module}/files/docker.asc")`, "imports https://example.com/docker.asc"},
		},
	} {
		res := convertWithKey(t, c.tasks)
		if res.Converted != 2 || len(res.Review) != 0 {
			t.Errorf("%s: converted %d, review %+v", name, res.Converted, res.Review)
		}
		for _, want := range c.wants {
			if !strings.Contains(string(res.HCL), want) {
				t.Errorf("%s: output lacks %q:\n%s", name, want, res.HCL)
			}
		}
	}
}

func TestLeavesKeyTasksItCantFold(t *testing.T) {
	const repo = "    - apt_repository: {repo: 'deb https://example.com/r noble main'}\n"
	for name, c := range map[string]struct{ tasks, reason string }{
		"apt_key alone":      {"    - apt_key: {url: 'https://example.com/docker.asc'}\n", "trusts it for every repository"},
		"rpm_key alone":      {"    - rpm_key: {key: 'https://example.com/docker.asc'}\n", "rpm's database"},
		"keyserver":          {"    - apt_key: {keyserver: keyserver.ubuntu.com, id: 9DC858229FC7DD38854AE2D88D81803C0EBFCD88}\n" + repo, "keyserver"},
		"key task with when": {"    - apt_key: {url: 'https://example.com/docker.asc'}\n      when: x\n" + repo, "doesn't name a key file"},
		"other gpgkey": {"    - rpm_key: {key: 'https://example.com/other.asc'}\n" +
			"    - yum_repository: {name: d, baseurl: 'https://example.com/', gpgcheck: true, gpgkey: 'https://example.com/docker.asc'}\n", "rpm's database"},
		"absent": {"    - rpm_key: {key: 'https://example.com/docker.asc', state: absent}\n", "removing a key"},
	} {
		res := convertWithKey(t, c.tasks)
		found := false
		for _, r := range res.Review {
			found = found || strings.Contains(r.Reason, c.reason)
		}
		if !found {
			t.Errorf("%s: no review with %q: %+v", name, c.reason, res.Review)
		}
	}
}
