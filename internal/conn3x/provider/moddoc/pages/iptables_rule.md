Use `iptables_rule` on a host that runs neither firewalld nor ufw and keeps its firewall in plain iptables. Each step is one rule in one chain, and the rest of the chain is left alone, so it sits happily beside rules Docker, Kubernetes or an old script put there. To own a whole table instead, use [`nftables`](/modules/nftables).

## Example usage

Let SSH in, then replies to connections the host made:

```hcl
step "ssh" {
  iptables_rule {
    chain            = "INPUT"
    protocol         = "tcp"
    destination_port = "22"
    jump             = "ACCEPT"
    comment          = "ssh, managed by Conn3x"
    confirm_after    = "60s"
  }
}

step "replies" {
  iptables_rule {
    chain    = "INPUT"
    ctstate  = ["ESTABLISHED", "RELATED"]
    jump     = "ACCEPT"
    position = "insert"
  }
}
```

Open the web ports to one network, over IPv4 and IPv6, and keep both across reboots on Debian or Ubuntu:

```hcl
step "persistent" {
  package {
    name = "iptables-persistent"
  }
}

step "web" {
  for_each   = { ipv4 = "10.0.0.0/8", ipv6 = "fd00::/8" }
  depends_on = [conn3x_package.docs__persistent]

  iptables_rule {
    ip_version        = item.key
    chain             = "INPUT"
    protocol          = "tcp"
    source            = item.value
    destination_ports = ["80", "443"]
    jump              = "ACCEPT"
    persist           = true
  }
}
```

The address is the step's resource address, `conn3x_package.CIRCUIT__STEP`, here in a circuit named `docs`.
<!-- reference -->
## How it works

**Reading.** Every refresh runs `iptables -C` with the rule's own arguments, and its exit status says whether the rule is there. A rule deleted by hand shows as out of sync, and the next apply adds it back. iptables answers `-C` the same way for a chain that doesn't exist, so a missing chain reads as a missing rule, and the apply then fails naming the chain. Removing a step whose chain is gone succeeds.

**Applying.** Conn3x adds the rule with `iptables -A`, at the end of the chain, or `iptables -I` with `position = "insert"`: at the top, or at `rule_num`. Where the rule goes only counts when it's added. A rule that's already somewhere in the chain is in sync, wherever it is. Every argument goes to `iptables` as one quoted word, so a `comment` with quotes or a `$` in it arrives as written. `-w` waits for the xtables lock, so the rules of a `for_each` step take turns.

**The rule.** `table`, `chain`, `protocol`, `source`, `destination`, the ports, the interfaces, `ctstate`, `jump` and `comment` are the rule itself, and changing any of them replaces it: the old rule is deleted and the new one added. `destination_ports` becomes `-m multiport --dports`, `ctstate` becomes `-m conntrack --ctstate` and `comment` becomes `-m comment --comment`. Ports need `protocol` to be `tcp`, `udp`, `udplite`, `sctp` or `dccp`. `source` and `destination` are one address or one CIDR network of the step's `ip_version`; a host name or a comma list would make iptables add several rules, which can't be checked as one.

**IPv6.** `ip_version = "ipv6"` uses `ip6tables`. One step is one version, so a rule for both is two steps, or one with `for_each` as above.

**Reboots.** iptables forgets everything at reboot. With `persist = true`, Conn3x saves the whole table after each change with `iptables-save`, to `/etc/iptables/rules.v4` (or `rules.v6`) where Debian and Ubuntu's `iptables-persistent` loads it at boot, or `/etc/sysconfig/iptables` (or `ip6tables`) for the Red Hat family's `iptables-services`, whose `iptables` service must be enabled. The save holds every rule in the table, not only Conn3x's. When neither package is on the host, the step fails and says which to install, rather than write a file nothing reads. A hand edit of the saved file isn't seen: refreshes read the running rules.

**Confirming.** A wrong rule on INPUT is how you lose SSH. With `confirm_after`, the host schedules the command that takes the change back with `systemd-run` before Conn3x makes it, and Conn3x cancels it once a new login works. If that login doesn't come, the host takes the change back by itself, and saves the table again with `persist`. Undoing a removal appends the rule again rather than putting it where it was. `confirm_after` is between `10s` and `1h` and needs systemd on the host.

## Removal

When you delete an `iptables_rule` step, `on_remove` decides what happens on the host. The default is `"delete"`, unlike most modules: Conn3x runs `iptables -D` for the rule, and saves the table with `persist`, so a port you stop managing doesn't stay open. `"forget"` leaves the rule in place.

## From Ansible

`conn3x convert ansible` turns `ansible.builtin.iptables` tasks into `iptables_rule` steps, argument for argument. `action: insert` becomes `position = "insert"`, and `ip_version: both` becomes two steps, one per version. A `match` that only names what another argument already loads, such as `tcp` with `protocol: tcp` or `conntrack` with `ctstate`, is dropped. Ansible's module never saves the rules, so neither does the converted step: add `persist = true` to keep them across reboots.

A task stays for review when it sets `policy`, `flush` or `chain_management`, which change a whole chain; `goto`, `to_ports`, `to_destination` or `to_source`, the NAT and jump options a rule step doesn't carry yet; `limit`; `state: absent`; a `match` with options of its own; a value negated with `!`; or any other argument.
