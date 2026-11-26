#!/bin/sh
# Reads stdin, as an installer asking a question might: it must get
# nothing, not the rest of this script.
read -r answer || true
mkdir -p "$2/bin"
echo "run ${answer:-unasked}" >>"$2/runs"
touch "$2/bin/app"
