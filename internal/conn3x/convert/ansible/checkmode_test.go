// Copyright (c) The Conn3x Authors
// SPDX-License-Identifier: MPL-2.0

package ansible

import (
	"strings"
	"testing"
)

// ansible_check_mode is false on a real run, which an apply always is:
// not ansible_check_mode drops out of a when, ignore_errors of it goes,
// and a task that needs check mode stays for review.
func TestCheckMode(t *testing.T) {
	dir := writeRole(t, map[string]string{
		"defaults/main.yml": "php_enable_php_fpm: true\n",
		"tasks/main.yml": `- name: FPM
  file: {path: /etc/php-fpm.d, state: directory}
  when:
    - php_enable_php_fpm
    - not ansible_check_mode
  notify: restart docker
- name: Inline
  file: {path: /srv/a, state: directory}
  when: php_enable_php_fpm and not ansible_check_mode
- name: Alone
  file: {path: /srv/b, state: directory}
  when: not ansible_check_mode
- name: Written false
  file: {path: /srv/c, state: directory}
  ignore_errors: false
- name: Dry run only
  file: {path: /srv/d, state: directory}
  when: ansible_check_mode
`,
		"handlers/main.yml": `- name: restart docker
  service: {name: docker, state: restarted}
  ignore_errors: "{{ ansible_check_mode }}"
`,
	})
	res, err := ConvertRole(dir)
	if err != nil {
		t.Fatal(err)
	}
	var hcl strings.Builder
	for _, b := range res.Files {
		hcl.Write(b)
	}
	if res.Converted != 4 || len(res.Review) != 1 || res.Review[0].Reason != checkModeReason {
		t.Fatalf("converted %d, review %+v\n%s", res.Converted, res.Review, hcl.String())
	}
	out := hcl.String()
	if strings.Contains(out, "not ansible_check_mode") || strings.Count(out, "var.php_enable_php_fpm") < 2 || !strings.Contains(out, `"docker"`) {
		t.Errorf("want both whens on the variable alone and the handler converted:\n%s", out)
	}
}
