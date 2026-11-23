package ansible

import "strings"

// capabilitiesModule turns one capability on a file into a file_capabilities
// step. Ansible adds or removes the one it names; the step owns the file's
// whole set, so it converts only when nothing else in the play sets the file.
func capabilitiesModule(in *input) ([]step, string) {
	if in.loop {
		return nil, "loops over capabilities, and a file_capabilities step owns a file's whole set; write one step listing them all"
	}
	in.state("present", "present")
	path, capability := in.str("path"), in.str("capability")
	if in.problem != "" {
		return nil, in.problem
	}
	if in.capTasks > 1 {
		return nil, "is one of several capabilities tasks for " + path + ", and a file_capabilities step owns the file's whole set; write one step listing them all"
	}
	if strings.Contains(capability, "-") {
		return nil, "takes capabilities off with -, and a file_capabilities step lists what the file keeps; write the set it should end with"
	}
	return one("file_capabilities", []attr{s("path", path), {key: "capabilities", val: stringList([]string{capability})}},
		"TODO(convert): This step owns every capability on "+path+" and takes off any it doesn't list. Add any the file needs that this task didn't set.")
}
