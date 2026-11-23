package ansible

import "regexp"

var apacheModName = regexp.MustCompile(`^[A-Za-z0-9_][A-Za-z0-9_.-]*$`)

// apache2ModuleModule turns a2enmod and a2dismod into guarded command steps,
// as circuit-apache does. Both exist only on Debian and Ubuntu.
func apache2ModuleModule(in *input) ([]step, string) {
	if in.loop {
		return nil, "loops over modules; write one task for each"
	}
	st := in.state("present", "present", "absent")
	name := in.str("name")
	force := in.bool("force", false)
	in.ignore("identifier", "warn_mpm_absent") // only change how Ansible checks the result
	if in.problem != "" {
		return nil, in.problem
	}
	if in.has("ignore_configcheck") {
		return nil, "sets ignore_configcheck, which hides a broken configuration a2enmod would report"
	}
	if !apacheModName.MatchString(name) {
		return nil, "has the module name " + shellQuote(name) + ", which isn't a plain module name"
	}
	load := "/etc/apache2/mods-enabled/" + name + ".load"
	cmd, unless := "a2enmod -q "+name, "test -e "+load
	if st == "absent" {
		cmd, unless = "a2dismod -q "+name, "! test -e "+load
		if force {
			cmd = "a2dismod -q -f " + name
		}
	}
	return one("command", []attr{s("command", cmd), s("unless", unless)},
		"a2enmod and a2dismod exist only on Debian and Ubuntu, as Ansible's apache2_module does.")
}
