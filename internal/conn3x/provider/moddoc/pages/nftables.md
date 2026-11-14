Use `nftables` to own one nftables table on a host that runs plain nftables, without firewalld or ufw on top: a minimal server, a router, an appliance. You write the table's chains and rules in nft's own syntax, and Conn3x loads them in one transaction, keeps them across reboots, and shows a rule someone added by hand as drift.

## Example usage

Let SSH and HTTPS in, and drop the rest:

```hcl
step "nft" {
  package {
    name = "nftables"
  }
}

step "firewall" {
  nftables {
    table         = "conn3x"
    confirm_after = "60s"
    content       = <<-NFT
      chain input {
        type filter hook input priority 0; policy drop;
        ct state established,related accept
        iif lo accept
        tcp dport { 22, 443 } accept
      }
    NFT
  }
}
```

`confirm_after` is the safety net for a rule that could lock you out, as on the other firewall steps.
<!-- reference -->
## How it works

**The table is yours, whole.** `content` is the body of `table FAMILY NAME { ... }`: its chains, sets and rules. Anything else in that table goes on the next apply. Other tables, such as one a container runtime made, are left alone. `content` can't reach past its own table: `flush ruleset`, `include`, another `table` and `define` are refused.

**Applying.** Conn3x checks the whole table with `nft -c` first. If nft refuses it, the step fails with nft's own words, and nothing has changed. Then it loads the table in one transaction, which makes it if it's missing, deletes it, and defines it again, so there's never a moment with half the old rules. The table goes in `/etc/conn3x/nftables/FAMILY-NAME.nft`, and a unit of its own, `conn3x-nft-FAMILY-NAME.service`, loads it at every boot. That works the same whatever the distribution's own `nftables.conf` does.

**Reading.** nft rewrites rules when it lists them, so Conn3x doesn't compare your text with its listing. It keeps what nft listed right after the load, and on every plan compares that with what nft lists now. A rule added or deleted by hand, or a table someone flushed, shows as `in_sync = false`, and the next apply loads yours again.

**`confirm_after`.** Before a change, the host records the table as it was and schedules putting it back. After the change, Conn3x logs in again over a new connection and cancels that. If the change locked it out, the login never comes, and the host puts the old table back by itself. Needs systemd.

**Changes.** Changing `content` reloads the table in place. Changing `family` or `table` replaces the step.

## Removal

`on_remove = "delete"`, the default, deletes the table and its boot unit when the step goes, as with every firewall step. `on_remove = "forget"` leaves them.
