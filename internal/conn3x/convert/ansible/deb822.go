package ansible

import (
	"fmt"
	"strings"

	"github.com/opentofu/opentofu/internal/conn3x/modules/pkg"
	"github.com/opentofu/opentofu/internal/conn3x/modules/repo"
)

// deb822Options are deb822_repository's arguments a repository step has
// no counterpart for; each keeps the task for review.
var deb822Options = []string{"architectures", "trusted", "allow_insecure", "allow_weak", "allow_downgrade_to_insecure",
	"check_valid_until", "check_date", "date_max_future", "by_hash", "inrelease_path", "languages", "pdiffs", "targets",
	"include", "exclude", "suite_check", "signed_by_fingerprint"}

// deb822RepositoryModule turns a deb822_repository task into a repository
// step, which writes the same kind of .sources file with Signed-By.
func deb822RepositoryModule(in *input) ([]step, string) {
	if in.loop {
		return nil, "loops over repositories, which the converter can't translate yet; write one task for each"
	}
	in.state("present", "present")
	name := in.str("name")
	uris, suites, components := in.list("uris"), in.list("suites"), in.list("components")
	types := in.list("types")
	signedBy := strings.TrimSpace(in.str("signed_by"))
	enabled := in.bool("enabled", true)
	in.ignore("install_python_debian", "mode") // only what Ansible needs; the step writes 0644
	if in.problem != "" {
		return nil, in.problem
	}
	for _, k := range deb822Options {
		if in.has(k) {
			return nil, "sets " + k + ", which a repository step doesn't have"
		}
	}
	if !enabled {
		return nil, "sets enabled: no; Conn3x always enables the repository"
	}
	if len(types) > 0 && (len(types) != 1 || types[0] != "deb") {
		return nil, "sets types other than [deb]; a repository step adds binary packages only, not deb-src"
	}
	if len(uris) != 1 {
		return nil, "doesn't set exactly one URI; a repository step has one URL"
	}
	if len(suites) != 1 {
		return nil, "doesn't set exactly one suite; a repository step converts one suite at a time"
	}
	var keyAttr attr
	note := ""
	switch {
	case signedBy == "":
		return nil, "doesn't set signed_by; a repository step trusts one key for this repository only, and the converter can't tell which"
	case strings.HasPrefix(signedBy, "-----BEGIN PGP PUBLIC KEY BLOCK-----"):
		keyAttr = s("key", signedBy+"\n")
	case strings.Contains(signedBy, "://") || strings.HasPrefix(signedBy, "/"):
		key, file, reason := in.repoKey(signedBy)
		if reason != "" {
			return nil, reason
		}
		signedBy = key
		keyAttr = attr{key: "key", raw: "file(" + moduleFile(file) + ")"}
		note = fmt.Sprintf("Check that %s is the key at %s.", file, in.str("signed_by"))
	default:
		return nil, "names its key by fingerprint; a repository step needs the armored key itself, so save it under files/ and point signed_by at it"
	}
	r := repo.Repo{Name: name, URL: uris[0], Key: signedBy, Suites: suites, Components: components}
	if err := r.Validate(pkg.Deb); err != nil {
		return nil, "can't be a repository step: " + err.Error()
	}
	attrs := []attr{s("name", name), s("url", uris[0]), keyAttr, {key: "suites", val: stringList(suites)}}
	if len(components) > 0 {
		attrs = append(attrs, attr{key: "components", val: stringList(components)})
	}
	var notes []string
	if note != "" {
		notes = append(notes, note)
	}
	return one("repository", attrs, notes...)
}
