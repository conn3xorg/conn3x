// Copyright (c) The Conn3x Authors
// SPDX-License-Identifier: MPL-2.0

package firewall

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

// The undo of a delete runs against rules files as they are after the
// delete and a stand-in ufw that reports what it would run, and adds a
// tuple to the IPv4 file for an IPv4 rule, as ufw does.
func TestUFWRestorePosition(t *testing.T) {
	if _, err := exec.LookPath("awk"); err != nil {
		t.Skip("no awk")
	}
	const (
		head   = "*filter\n:ufw-user-input - [0:0]\n### RULES ###\n\n"
		allow4 = "### tuple ### allow tcp 22 0.0.0.0/0 any 0.0.0.0/0 in\n"
		deny4  = "### tuple ### deny any 22 0.0.0.0/0 any 0.0.0.0/0 in\n"
		web4   = "### tuple ### allow any 80 0.0.0.0/0 any 0.0.0.0/0 in\n"
		pg4    = "### tuple ### allow tcp 5432 0.0.0.0/0 any 10.0.0.0/8 in\n"
		allow6 = "### tuple ### allow tcp 22 ::/0 any ::/0 in\n"
		deny6  = "### tuple ### deny any 22 ::/0 any ::/0 in\n"
		web6   = "### tuple ### allow any 80 ::/0 any ::/0 in\n"
		dns6   = "### tuple ### allow any 53 ::/0 any fd00::/8 in\n"
		tail   = "\n### END RULES ###\nCOMMIT\n"
		// "ufw allow Multi" with ports=80,443/tcp|8080/udp: one rule, two
		// tuples per family, as ufw 0.36.2 writes it.
		multi4 = "### tuple ### allow tcp 80,443 0.0.0.0/0 any 0.0.0.0/0 Multi - in\n### tuple ### allow udp 8080 0.0.0.0/0 any 0.0.0.0/0 Multi - in\n"
		multi6 = "### tuple ### allow tcp 80,443 ::/0 any ::/0 Multi - in\n### tuple ### allow udp 8080 ::/0 any ::/0 Multi - in\n"
		// The same profile on an interface, and routed: ufw 0.36.2's
		// "allow in on eth0 to any app Multi" and "route allow in on eth0
		// out on eth1 to any app Multi". Each is one rule.
		multiIf4    = "### tuple ### allow tcp 80,443 0.0.0.0/0 any 0.0.0.0/0 Multi - in_eth0\n### tuple ### allow udp 8080 0.0.0.0/0 any 0.0.0.0/0 Multi - in_eth0\n"
		multiRoute4 = "### tuple ### route:allow tcp 80,443 0.0.0.0/0 any 0.0.0.0/0 Multi - in_eth0!out_eth1\n### tuple ### route:allow udp 8080 0.0.0.0/0 any 0.0.0.0/0 Multi - in_eth0!out_eth1\n"
		// Two plain rules with the same comment are still two rules.
		noted4 = "### tuple ### allow tcp 80 0.0.0.0/0 any 0.0.0.0/0 in comment=776562\n### tuple ### allow tcp 443 0.0.0.0/0 any 0.0.0.0/0 in comment=776562\n"
	)
	ssh22 := UFWRule{Action: "allow", Port: "22/tcp"}
	// A blocklist big enough that its listing passes the 128 KiB a single
	// argument or environment string may hold on Linux.
	var block strings.Builder
	for i := 0; i < 3000; i++ {
		fmt.Fprintf(&block, "### tuple ### deny any any 0.0.0.0/0 any 198.%d.%d.0/24 in\n", i/250, i%250)
	}
	for _, c := range []struct {
		name             string
		rule             UFWRule
		before4, before6 string
		after4, after6   string
		want             string
	}{
		{"both above a deny", ssh22,
			allow4 + deny4 + web4, allow6 + deny6 + web6 + dns6,
			deny4 + web4, deny6 + web6 + dns6,
			"insert 1 allow from 0.0.0.0/0 to any port 22 proto tcp\ninsert 4 allow from ::/0 to any port 22 proto tcp\n"},
		{"both, last in IPv4, first in IPv6", ssh22,
			deny4 + allow4, allow6 + dns6 + deny6,
			deny4, dns6 + deny6,
			"allow from 0.0.0.0/0 to any port 22 proto tcp\ninsert 3 allow from ::/0 to any port 22 proto tcp\n"},
		{"both, last in each", ssh22,
			deny4 + allow4, deny6 + allow6,
			deny4, deny6,
			"allow from 0.0.0.0/0 to any port 22 proto tcp\nallow from ::/0 to any port 22 proto tcp\n"},
		{"IPv4 only", UFWRule{Action: "allow", Port: "5432/tcp", From: "10.0.0.0/8"},
			web4 + pg4 + deny4, web6 + deny6,
			web4 + deny4, web6 + deny6,
			"insert 2 allow from 10.0.0.0/8 to any port 5432 proto tcp\n"},
		{"IPv6 only", UFWRule{Action: "allow", Port: "53", From: "fd00::/8"},
			web4 + deny4, web6 + dns6 + deny6,
			web4 + deny4, web6 + deny6,
			"insert 4 allow from fd00::/8 to any port 53\n"},
		{"IPv6 off", ssh22, allow4 + deny4, "", deny4, "",
			"insert 1 allow from 0.0.0.0/0 to any port 22 proto tcp\n"},
		{"only the IPv6 half deleted", ssh22,
			allow4 + deny4, allow6 + deny6,
			allow4 + deny4, deny6,
			"insert 3 allow from ::/0 to any port 22 proto tcp\n"},
		{"above a blocklist past the argument limit", ssh22,
			allow4 + block.String(), "",
			block.String(), "",
			"insert 1 allow from 0.0.0.0/0 to any port 22 proto tcp\n"},
		{"below a profile rule of two tuples", ssh22,
			multi4 + allow4 + deny4, multi6 + allow6 + deny6,
			multi4 + deny4, multi6 + deny6,
			"insert 2 allow from 0.0.0.0/0 to any port 22 proto tcp\ninsert 5 allow from ::/0 to any port 22 proto tcp\n"},
		// Foothills' case on #1403: ufw numbers these 1 to 4, so the allow is 2.
		{"between interface and routed profile rules", ssh22,
			multiIf4 + allow4 + multiRoute4 + deny4, "",
			multiIf4 + multiRoute4 + deny4, "",
			"insert 2 allow from 0.0.0.0/0 to any port 22 proto tcp\n"},
		{"below two commented rules", ssh22, noted4 + allow4 + deny4, "", noted4 + deny4, "",
			"insert 3 allow from 0.0.0.0/0 to any port 22 proto tcp\n"},
		{"never deleted", ssh22, allow4 + deny4, allow6 + deny6, allow4 + deny4, allow6 + deny6, ""},
	} {
		t.Run(c.name, func(t *testing.T) {
			dir := t.TempDir()
			old := ufwFiles
			ufwFiles = [2]string{filepath.Join(dir, "user.rules"), filepath.Join(dir, "user6.rules")}
			defer func() { ufwFiles = old }()
			for i, s := range []string{c.after4, c.after6} {
				if err := os.WriteFile(ufwFiles[i], []byte(head+s+tail), 0o600); err != nil {
					t.Fatal(err)
				}
			}
			cmd, err := c.rule.restore([2]string{ufwTuples(head + c.before4 + tail), ufwTuples(head + c.before6 + tail)})
			if err != nil {
				t.Fatal(err)
			}
			stub := `flock() { shift; "$@"; }
ufw() { echo "$*"; case "$*" in *:*) ;; *) echo '### tuple ### restored' >> "$V4" ;; esac; }
`
			// On stdin, as revert.sh is run from a file: an argument is
			// capped at 128 KiB on Linux.
			sh := exec.Command("sh")
			sh.Stdin = strings.NewReader(stub + cmd + "\n")
			sh.Env = append(os.Environ(), "V4="+ufwFiles[0])
			out, err := sh.CombinedOutput()
			if err != nil {
				t.Fatalf("%v: %s", err, out)
			}
			if string(out) != c.want {
				t.Errorf("got %q, want %q", out, c.want)
			}
		})
	}
}
