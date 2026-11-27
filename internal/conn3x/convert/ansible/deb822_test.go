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
		"by fingerprint":            "deb822_repository: {" + deb822Docker + ", signed_by: 9DC858229FC7DD38854AE2D88D81803C0EBFCD88}",
		"its key by fingerprint":    "deb822_repository: {" + deb822Docker + ", signed_by: '9DC8 5822 9FC7 DD38 854A  E2D8 8D81 803C 0EBF CD88'}",
		`"files/docker.asc", which`: "deb822_repository: {" + deb822Docker + ", signed_by: files/docker.asc}",
		`"docker.asc", which`:       "deb822_repository: {" + deb822Docker + ", signed_by: docker.asc}",
		"exactly one URI":           "deb822_repository: {name: d, uris: ['https://a.example/r', 'https://b.example/r'], suites: [noble], components: [main]" + key + "}",
		"not deb-src":               "deb822_repository: {name: d, types: [deb, deb-src], uris: 'https://example.com/r', suites: [noble], components: [main]" + key + "}",
		"sets architectures":        "deb822_repository: {" + deb822Docker + ", architectures: [amd64]" + key + "}",
		"enabled: no":               "deb822_repository: {" + deb822Docker + ", enabled: false" + key + "}",
		`state "absent"`:            "deb822_repository: {name: docker, state: absent}",
		"doesn't set signed_by":     "deb822_repository: {" + deb822Docker + "}",
		"save https://example.com":  "deb822_repository: {" + deb822Docker + ", signed_by: 'https://example.com/missing.asc'}",
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

// Each step that reads a role's file with file() gets the file copied into
// the circuit, byte for byte, or the circuit fails at plan.
func TestRoleCopiesEveryFileItReads(t *testing.T) {
	key := "-----BEGIN PGP PUBLIC KEY BLOCK-----\n\nmDMEZ1469\n-----END PGP PUBLIC KEY BLOCK-----\n"
	for file, task := range map[string]string{
		"files/example.asc": "deb822_repository: {name: example, uris: 'https://repo.example.com/debian', suites: [stable], components: [main], signed_by: /etc/apt/keyrings/example.asc}",
		"files/apt.asc":     "apt_repository: {repo: 'deb [signed-by=/etc/apt/keyrings/apt.asc] https://repo.example.com/debian stable main'}",
		"files/RPM-KEY":     "yum_repository: {name: example, baseurl: 'https://repo.example.com/el9', gpgcheck: true, gpgkey: 'https://repo.example.com/RPM-KEY'}",
		"files/example.key": "zypper_repository: {name: example, repo: 'https://repo.example.com/suse', auto_import_keys: true}",
		"files/app.conf":    "win_copy: {src: app.conf, dest: 'C:\\\\app\\\\app.conf'}",
	} {
		res, err := ConvertRole(writeRole(t, map[string]string{
			"tasks/main.yml": "- name: Task\n  " + task + "\n",
			file:             key,
			"meta/main.yml":  "galaxy_info: {}\n",
		}))
		if err != nil {
			t.Fatal(err)
		}
		if res.Converted != 1 || len(res.Review) != 0 {
			t.Errorf("%s: converted %d, review %+v", file, res.Converted, res.Review)
		}
		if got, ok := res.Files[file]; !ok || string(got) != key {
			t.Errorf("%s: circuit has %q (present %v)", file, got, ok)
		}
	}
}
