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

  For `nodejs`, it also reads the Node.js security working group's
  [core vulnerability data](https://github.com/nodejs/security-wg/tree/main/vuln/core),
  since Node.js advisories reach neither OSV nor GitHub's. It has no dates,
  so a CVE is reported when its vulnerable range takes in a full version a
  circuit pins, such as `26.13.0`, and no earlier issue named it.

  It also reads the vendor RSS feeds in `feeds`, such as Oracle's security
  alerts. A vendor's advisory names its CVEs days before distros ship a fix
  and OSV lists them, so each new item opens an issue of its own, naming the
  entries the feed may cover.

  It opens one `upstream-advisory` issue per piece of software for
  advisories no earlier issue listed. Each issue names the circuits that
  install it, the fixed versions, and what to check.
- **`.github/workflows/govulncheck.yml`** fails a PR, and the daily run, when
  `conn3x` or `conn3x-agent` calls code with a known Go vulnerability. A
  failed daily run opens an issue too.

## Keeping the watchlist current

Each `pinned` default is generated: `scripts/gen_watchlist.py` reads it from
the circuit's latest tag, and the advisory watch runs it before every run.
Run it after a circuit release and commit the result, so the file in the
repository says the same:

```sh
python3 scripts/gen_watchlist.py
```

Everything else is kept by hand.

When a circuit starts installing something new, add it to `watchlist.json`
in the same change: its package names, binary and source both (OSV's
Debian, Ubuntu and Rocky feeds go by the source package, such as
`openjdk-25` for `openjdk-25-jre-headless`; `apt-cache show` gives it as
`Source:`, and `dnf repoquery --qf '%{sourcerpm}'` as the SRPM), OSV packages, upstream GitHub
repository, images, and any version the circuit pins by default. An entry
looks like this:

```json
{"name": "nginx", "circuits": ["circuit-nginx"], "packages": ["nginx"],
 "osv": [], "github": [], "images": ["docker.io/library/nginx"], "pinned": []}
```

A vendor that publishes a security feed, rather than advisories in OSV or on
GitHub, goes in `feeds`, with the entries it may cover:

```json
{"name": "Oracle", "url": "https://www.oracle.com/.../rss-otn-sec.xml",
 "entries": ["openjdk", "mysql"]}
```

Software published only on Codeberg or GitLab, such as Forgejo and GitLab,
has no source here yet, beyond its vendor package names. Check their
security releases by hand.

To try a change without opening issues:

```sh
python3 scripts/advisory_watch.py --days 7 --dry-run
```

`--backfill` looks back 30 days instead of 7, for advisories published
before an entry was watched.
