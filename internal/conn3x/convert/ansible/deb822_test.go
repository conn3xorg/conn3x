package ansible

import (
	"strings"
	"testing"
)

const deb822Docker = "name: docker, types: [deb], uris: 'https://download.docker.com/linux/ubuntu', suites: [noble], components: [stable]"

func TestConvertsDeb822Repository(t *testing.T) {
	inline := strings.ReplaceAll(strings.TrimSuffix(armoredKey, "\n"), "\n", "\n          ")
	for task, wants := range map[string][]string{
		"ansible.builtin.deb822_repository: {" + deb822Docker + ", signed_by: 'https://download.docker.com/linux/ubuntu/docker.asc'}": {
			`name       = "docker"`, `url        = "https://download.docker.com/linux/ubuntu"`,
			`key        = file("${path.module}/files/docker.asc")`, `suites     = ["noble"]`, `components = ["stable"]`,
		},
		"deb822_repository: {name: d, uris: 'https://example.com/r', suites: [noble], components: [main], signed_by: /etc/apt/keyrings/docker.asc, install_python_debian: true}":            {`key        = file(`},
		"deb822_repository:\n        name: d\n        uris: 'https://example.com/r'\n        suites: [noble]\n        components: [main]\n        signed_by: |\n          " + inline + "\n": {`key        = "-----BEGIN PGP PUBLIC KEY BLOCK-----\nabc\n`},
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

func TestLeavesDeb822RepositoriesItCantProve(t *testing.T) {
	key := ", signed_by: 'https://example.com/docker.asc'"
	for reason, task := range map[string]string{
		"by fingerprint":           "deb822_repository: {" + deb822Docker + ", signed_by: 9DC858229FC7DD38854AE2D88D81803C0EBFCD88}",
		"exactly one URI":          "deb822_repository: {name: d, uris: ['https://a.example/r', 'https://b.example/r'], suites: [noble], components: [main]" + key + "}",
		"not deb-src":              "deb822_repository: {name: d, types: [deb, deb-src], uris: 'https://example.com/r', suites: [noble], components: [main]" + key + "}",
		"sets architectures":       "deb822_repository: {" + deb822Docker + ", architectures: [amd64]" + key + "}",
		"enabled: no":              "deb822_repository: {" + deb822Docker + ", enabled: false" + key + "}",
		`state "absent"`:           "deb822_repository: {name: docker, state: absent}",
		"doesn't set signed_by":    "deb822_repository: {" + deb822Docker + "}",
		"save https://example.com": "deb822_repository: {" + deb822Docker + ", signed_by: 'https://example.com/missing.asc'}",
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
