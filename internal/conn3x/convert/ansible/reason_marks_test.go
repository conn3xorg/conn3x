// Copyright (c) The Conn3x Authors
// SPDX-License-Identifier: MPL-2.0

package ansible

import (
	"strings"
	"testing"
)

func TestReviewReasonsDisplayReferences(t *testing.T) {
	for name, tc := range map[string]struct{ defaults, tasks, want string }{
		"package URL": {
			"nodejs_version: 22\n",
			"- name: Install repository\n  package:\n    name: https://rpm.example.test/pub_{{ nodejs_version }}/release.rpm\n",
			"installs https://rpm.example.test/pub_${var.nodejs_version}/release.rpm",
		},
		"missing template": {
			"",
			"- name: Render template\n  template:\n    src: '{{ item }}.j2'\n    dest: /tmp/synthetic.conf\n  loop: [missing]\n",
			"${item.value}.j2 was not found in the role's templates/",
		},
	} {
		t.Run(name, func(t *testing.T) {
			res, err := ConvertRole(writeRole(t, map[string]string{"defaults/main.yml": tc.defaults, "tasks/main.yml": tc.tasks}))
			if err != nil {
				t.Fatal(err)
			}
			if len(res.Review) != 1 {
				t.Fatalf("want one review reason, got %+v", res.Review)
			}
			reason := res.Review[0].Reason
			if strings.ContainsRune(reason, '\x00') || !strings.Contains(reason, tc.want) {
				t.Errorf("reason %q, want readable reference %q", reason, tc.want)
			}
		})
	}
}
