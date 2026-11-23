package ansible

import (
	"fmt"
	"strings"
)

// capabilitiesModule leaves every capabilities task for review. Ansible adds
// or removes the one capability it names and keeps the file's others; a
// file_capabilities step owns the whole set, so converting would take off
// what a package or another play gave the file. The converted circuit does
// less than the play, never more (#1262). The reasons say what to write.
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
		return nil, "takes capabilities off with -, and a file_capabilities step lists what the file keeps; write one with the set it should end with"
	}
	return nil, fmt.Sprintf("adds %s and keeps any other capabilities %s has, and a file_capabilities step takes off what it doesn't list; write one with the file's whole set, such as capabilities = [%q]", capability, path, capability)
}
