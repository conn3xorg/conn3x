package ansible

import (
	"strings"
	"testing"
)

// A register nothing reads doesn't stop its task, and a task that only
// refreshes the package lists drops whatever its when, so a register only
// that when reads counts as unread. A register a template reads still stops
// its task. The name is matched as a word anywhere in the role, so one that's
// also ordinary text, such as started, counts as read.
func TestUnreadRegisterConverts(t *testing.T) {
	res, err := ConvertRole(writeRole(t, map[string]string{
		"tasks/main.yml": `
- name: Install the repository package.
  package:
    name: example-release
  register: repo
- name: Refresh if the repository was added.
  apt: update_cache=yes
  when: repo is changed
- name: Start the service.
  service:
    name: example
    state: started
  register: service_result
- name: Look for the config.
  package:
    name: example-tools
  register: tools
- name: Write the config.
  template:
    src: example.conf.j2
    dest: /etc/example.conf
`,
		"templates/example.conf.j2": "{{ tools.changed }}\n",
	}))
	if err != nil {
		t.Fatal(err)
	}
	if res.Converted != 3 {
		t.Errorf("converted %d, want 3", res.Converted)
	}
	// The template stays too, for its own reason.
	if len(res.Review) != 2 || res.Review[0].Task != "Look for the config." || !strings.Contains(res.Review[0].Reason, "uses register") {
		t.Fatalf("review %+v", res.Review)
	}
	if !strings.Contains(string(res.Files["main.circuit.hcl"]), "only refreshes the package lists") {
		t.Errorf("the refresh has no note:\n%s", res.Files["main.circuit.hcl"])
	}
}
