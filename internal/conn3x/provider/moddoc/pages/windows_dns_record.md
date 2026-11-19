**Experimental.** New, and tested on GitHub's Windows Server 2022 and 2025 runners with the DNS Server role added, not yet on a domain controller. See [Windows readiness](https://github.com/conn3xorg/conn3x/blob/main/docs/windows-readiness.md).

Use `windows_dns_record` to keep a name's records in a zone on a Windows DNS server, usually a domain controller: the A records for a web farm, a CNAME for an app, a TXT record for a mail check. A circuit that builds a domain can then publish its own names, instead of someone adding them in the DNS console.

## Example usage

Two web servers behind one name:

```hcl
step "www" {
  windows_dns_record {
    zone   = "corp.example.com"
    name   = "www"
    type   = "A"
    values = ["10.0.1.11", "10.0.1.12"]
    ttl    = 300
  }
}
```

An alias for an app:

```hcl
step "intranet" {
  windows_dns_record {
    zone   = "corp.example.com"
    name   = "intranet"
    type   = "CNAME"
    values = ["web1.corp.example.com"]
  }
}
```

Run the step on the DNS server that holds the zone, such as a domain controller in the circuit's `hosts`.
<!-- reference -->
## How it works

**The set.** A step owns every record of its `type` that `name` has in `zone`. Values not listed are removed, and missing ones are added, so a step with two addresses makes a round robin, and changing one address leaves the other record alone.

**Reading.** On every plan, Conn3x reads the records with `Get-DnsServerResourceRecord`. Values compare the way DNS reads them: IPv6 addresses in any form, and host names without case or the trailing dot the server adds. `in_sync` is true when the values match and they have `ttl`.

**Applying.** Conn3x removes what isn't listed, adds what's missing, and sets a new `ttl` in place on the records that stay, so none of them disappears while it changes. A zone that isn't on the server is an error that says so.

**Changes.** Changing `values` or `ttl` updates the records in place. Changing `zone`, `name` or `type` replaces the step.

## Removal

`on_remove = "forget"`, the default, leaves the records. `on_remove = "delete"` removes every record of the step's type that the name has.

## From Ansible

`conn3x convert ansible` turns `win_dns_record` tasks, from `ansible.windows` or `community.windows`, into `windows_dns_record` steps for A, AAAA, CNAME, PTR and TXT records. `value`, or its alias `values`, becomes `values`. In Ansible too it's every record the name has of that type, and any other is removed. `ttl` carries over, and defaults to 3600 in both. A task stays a TODO, with the reason, for another record type, such as SRV or NS, for `state: absent`, which removes every record of the name, and for `computer_name`, `zone_scope`, `aging` or `allow_update_any`.
