# Copyright (c) The Conn3x Authors
# SPDX-License-Identifier: MPL-2.0
"""Print the staged changes as a GraphQL FileChanges object.

GitHub signs commits created through createCommitOnBranch, so the upstream
sync commits through the API instead of pushing a local, unsigned commit.
Run from the repository root after staging the changes.
"""

import base64
import json
import subprocess
import sys


def git(*args):
    return subprocess.run(["git", *args], check=True, capture_output=True).stdout


def main():
    entries = git("diff", "--cached", "--name-status", "-z", "--no-renames").split(b"\0")
    additions, deletions = [], []
    for status, path in zip(entries[0::2], entries[1::2]):
        name = path.decode()
        if status == b"D":
            deletions.append({"path": name})
        else:
            blob = git("show", f":{name}")
            additions.append({"path": name, "contents": base64.b64encode(blob).decode()})
    if not additions and not deletions:
        print("commit_payload: nothing staged", file=sys.stderr)
        return 1
    json.dump({"additions": additions, "deletions": deletions}, sys.stdout)
    return 0


if __name__ == "__main__":
    sys.exit(main())
