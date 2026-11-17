# Baseline checks

Find out which hosts break a security baseline, without changing anything on them. Three checks, modelled on CIS benchmark items, run as part of a plan: root can't log in over SSH, passwords expire within a year, and there are no world-writable files.

It uses the container from [try-it-locally](../try-it-locally), so start that first:

```sh
../try-it-locally/up.sh
```

Then plan:

```sh
conn3x init
conn3x plan
```

The plan changes nothing, and warns about the rules the host breaks. A fresh Rocky Linux 10 container breaks two:

```text
No changes. Your infrastructure matches the configuration.

Warning: Check block assertion failed
...
Root can log in over SSH on box.

Warning: Check block assertion failed
...
PASS_MAX_DAYS is over 365 on box.
```

Make a file anyone can write, and plan again to see the third:

```sh
podman exec conn3x-try sh -c 'touch /etc/oops && chmod 666 /etc/oops'
conn3x plan
```

The plan still exits 0. To fail a CI job on a check, read the warnings from `conn3x plan -json`. [Check a baseline without changing anything](https://docs.conn3x.org/guides/compliance-checks/) shows how, and explains each check.

Point `var.hosts` and the `ssh` blocks at your own servers to check them. Clean up with `../try-it-locally/down.sh` and `rm -rf .terraform*`.
