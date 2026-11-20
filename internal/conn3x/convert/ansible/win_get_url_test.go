// Copyright (c) The Conn3x Authors
// SPDX-License-Identifier: MPL-2.0

package ansible

import (
	"strings"
	"testing"
)

func TestConvertWinGetURL(t *testing.T) {
	const sum = "ec6af1ea0367d16dde6639a89a080a524cebc4d4bedfe00ed0cac4b865a918d8"
	for _, task := range []string{
		"ansible.windows.win_get_url: {url: 'https://example.com/7z.msi', dest: 'C:\\Temp\\7z.msi', checksum: " + sum + ", checksum_algorithm: sha256}",
		"win_get_url: {url: 'https://example.com/7z.msi', dest: 'C:\\Temp\\7z.msi', checksum: " + strings.ToUpper(sum) + ", checksum_algorithm: SHA256, force: false}",
	} {
		res := convertString(t, "- hosts: all\n  tasks:\n    - "+task+"\n")
		for _, w := range []string{"windows_download {", `url    = "https://example.com/7z.msi"`, `dest   = "C:\\Temp\\7z.msi"`, `sha256 = "` + sum + `"`} {
			if res.Converted != 1 || !strings.Contains(string(res.HCL), w) {
				t.Errorf("%s: converted %d, want %s in:\n%s", task, res.Converted, w, res.HCL)
			}
		}
	}
	for task, reason := range map[string]string{
		// Ansible's algorithm defaults to sha1.
		"ansible.windows.win_get_url: {url: 'https://e.com/a', dest: 'C:\\a', checksum: " + sum + "}":                                              "has no sha256 checksum",
		"ansible.windows.win_get_url: {url: 'https://e.com/a', dest: 'C:\\a'}":                                                                     "has no sha256 checksum",
		"ansible.windows.win_get_url: {url: 'https://e.com/a', dest: 'C:\\a', checksum: abc, checksum_algorithm: sha256}":                          "has no sha256 checksum",
		"ansible.windows.win_get_url: {url: 'https://e.com/a', dest: 'C:\\a', checksum: " + sum + ", checksum_algorithm: sha256, url_password: x}": "url_password",
	} {
		res := convertString(t, "- hosts: all\n  tasks:\n    - "+task+"\n")
		if res.Converted != 0 || len(res.Review) != 1 || !strings.Contains(res.Review[0].Reason, reason) {
			t.Errorf("%s: converted %d, review %+v", task, res.Converted, res.Review)
		}
	}
}
