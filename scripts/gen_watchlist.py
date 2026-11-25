# Copyright (c) The Conn3x Authors
# SPDX-License-Identifier: MPL-2.0
"""Brings the pinned defaults in security/watchlist.json up to each circuit's
latest release.

Every `pinned` item names a circuit and a variable, such as
`circuit-traefik` `traefik_version`, or a local, such as `local.version`, or
one field of an object variable, such as `release.tag`. This reads that value
from the .tf and .circuit.hcl files at the circuit's highest v* tag and writes
it into `default`. Everything else in the file is curated by hand and left as
it is. A circuit that can't be read keeps its old value, with a warning, so a
network blip can't empty the watchlist.

The advisory watch runs this before every run, so the issues it opens always
name the defaults a user gets today.

Usage: python3 scripts/gen_watchlist.py [--watchlist security/watchlist.json]
"""

import argparse
import io
import json
import os
import re
import subprocess
import tarfile
import urllib.request
from datetime import datetime, timezone

ORG = "conn3xorg"
TAG = re.compile(r"refs/tags/(v(\d+)\.(\d+)\.(\d+))$")


def latest_tag(circuit):
    """The highest vX.Y.Z tag on GitHub, or None."""
    out = subprocess.run(["git", "ls-remote", "--tags", "--refs", f"https://github.com/{ORG}/{circuit}"],
                         capture_output=True, text=True, check=False, timeout=60)
    tags = [m for m in map(TAG.search, out.stdout.split()) if m]
    if not tags:
        return None
    return max(tags, key=lambda m: tuple(int(x) for x in m.groups()[1:])).group(1)


def sources(circuit, tag):
    """The text of the circuit's top-level .tf and .circuit.hcl files at tag."""
    url = f"https://codeload.github.com/{ORG}/{circuit}/tar.gz/refs/tags/{tag}"
    with urllib.request.urlopen(urllib.request.Request(url, headers={"User-Agent": "conn3x-watchlist"}), timeout=60) as r:
        data = r.read()
    out = []
    with tarfile.open(fileobj=io.BytesIO(data)) as tar:
        for m in tar.getmembers():
            parts = m.name.split("/")
            # The archive's one top directory, then the file: only the circuit's root.
            if m.isfile() and len(parts) == 2 and parts[1].endswith((".tf", ".circuit.hcl")):
                out.append(tar.extractfile(m).read().decode("utf-8", "replace"))
    return "\n".join(out)


def mask(src):
    """src with strings and comments blanked, so braces inside them, like regex "{0,2}", don't count."""
    return re.sub(r'"(?:\\.|[^"\\\n])*"|(?:#|//)[^\n]*', lambda s: " " * len(s.group()), src)


def blocks(src, head):
    """Bodies of top-level blocks whose opening line matches head, such as
    `variable "x"` or `locals`."""
    out = []
    masked = mask(src)
    for m in re.finditer(rf"^{head}\s*\{{", src, re.M):
        depth, i = 1, m.end()
        while depth and i < len(masked):
            depth += {"{": 1, "}": -1}.get(masked[i], 0)
            i += 1
        out.append(src[m.end():i - 1])
    return out


def top_attr(body, key):
    """The raw value of key at the body's top level, or None."""
    depth = 0
    for line in body.splitlines():
        s = line.strip()
        if depth == 0 and re.match(rf"{re.escape(key)}\s*=", s):
            return s.split("=", 1)[1].strip()
        m = mask(s)
        depth += m.count("{") + m.count("[") + m.count("(") - m.count("}") - m.count("]") - m.count(")")
    return None


def literal(raw):
    """A plain string or number, unquoted; None for anything computed."""
    if raw is None:
        return None
    m = re.fullmatch(r'"((?:[^"\\$]|\\.)*)"', raw)
    if m:
        return m.group(1)
    return raw if re.fullmatch(r"[\d.]+", raw) else None


def default_of(src, variable):
    """The default of variable ("x", "local.x" or "x.field") in src, or None."""
    if variable.startswith("local."):
        name = variable[len("local."):]
        for body in blocks(src, "locals"):
            v = literal(top_attr(body, name))
            if v is not None:
                return v
        return None
    name, _, field = variable.partition(".")
    for body in blocks(src, rf'variable\s+"{re.escape(name)}"'):
        if not field:
            return literal(top_attr(body, "default"))
        obj = blocks(body, r"[ \t]*default\s*=")
        return literal(top_attr(obj[0], field)) if obj else None
    return None


def update(watchlist, read):
    """Sets every pinned default from read(circuit, variable), which gives the
    value or None. Returns (circuit, variable, old, new) for each change."""
    changes = []
    for e in watchlist["entries"]:
        for p in e.get("pinned", []):
            new = read(p["circuit"], p["variable"])
            if new is not None and new != p["default"]:
                changes.append((p["circuit"], p["variable"], p["default"], new))
                p["default"] = new
    return changes


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--watchlist", default=os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "security", "watchlist.json"))
    args = ap.parse_args()

    with open(args.watchlist) as f:
        watchlist = json.load(f)
    cache = {}

    def read(circuit, variable):
        if circuit not in cache:
            try:
                tag = latest_tag(circuit)
                cache[circuit] = (tag, sources(circuit, tag)) if tag else None
            except (OSError, subprocess.SubprocessError, tarfile.TarError) as e:
                print(f"::warning::{circuit}: {e}; its pinned defaults are left as they were")
                cache[circuit] = None
        if cache[circuit] is None:
            return None
        v = default_of(cache[circuit][1], variable)
        if v is None:
            print(f"::warning::{circuit} {cache[circuit][0]} has no literal default for {variable}; left as it was")
        return v

    changes = update(watchlist, read)
    for c, v, old, new in changes:
        print(f"{c} {v}: {old} -> {new}")
    if changes:
        watchlist["generated"] = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
        with open(args.watchlist, "w") as f:
            f.write(json.dumps(watchlist, indent=2, ensure_ascii=False) + "\n")
    print(f"{len(changes)} default(s) updated from {len(cache)} circuits' latest tags.")


if __name__ == "__main__":
    main()
