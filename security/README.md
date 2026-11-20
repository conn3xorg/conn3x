# Watching upstream advisories

The circuits install a lot of other people's software: nginx, PostgreSQL,
k3s, Grafana and well over a hundred more. When one of them publishes a
security fix, someone has to check whether a circuit's default version, a
pinned image or a docs example is affected. `watchlist.json` and two
workflows make sure that someone hears about it.

- **`.github/workflows/advisories.yml`** runs `scripts/advisory_watch.py`
  every six hours. For each entry in `watchlist.json` it looks up:
  - the distro packages in OSV, for every distro in `ecosystems`;
  - the `osv` packages, such as Go modules;
  - the `github` projects' own security advisories.

  It opens one `upstream-advisory` issue per piece of software for
  advisories no earlier issue listed. Each issue names the circuits that
  install it, the fixed versions, and what to check.
- **`.github/workflows/govulncheck.yml`** fails a PR, and the daily run, when
  `conn3x` or `conn3x-agent` calls code with a known Go vulnerability. A
  failed daily run opens an issue too.

## Keeping the watchlist current

When a circuit starts installing something new, add it to `watchlist.json`
in the same change: its package names, OSV packages, upstream GitHub
repository, images, and any version the circuit pins by default. An entry
looks like this:

```json
{"name": "nginx", "circuits": ["circuit-nginx"], "packages": ["nginx"],
 "osv": [], "github": [], "images": ["docker.io/library/nginx"], "pinned": []}
```

Software published only on Codeberg or GitLab, such as Forgejo and GitLab,
has no source here yet, beyond its vendor package names. Check their
security releases by hand.

To try a change without opening issues:

```sh
python3 scripts/advisory_watch.py --days 7 --dry-run
```
