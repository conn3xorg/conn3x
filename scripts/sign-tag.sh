#!/usr/bin/env bash
# Copyright (c) The Conn3x Authors
# SPDX-License-Identifier: MPL-2.0
#
# Make an annotated tag signed with gitsign, Sigstore's keyless signing,
# from the GitHub Actions workflow's own identity, and check the signature
# before anything else sees the tag. Nothing is pushed.
#
#   scripts/sign-tag.sh TAG COMMIT IDENTITY_REGEXP
#
# IDENTITY_REGEXP is the workflow the certificate must name, for example
# ^https://github.com/conn3xorg/conn3x/\.github/workflows/release\.yml@refs/heads/main$
#
# Needs gitsign on PATH and a job with id-token: write.
set -euo pipefail

tag=$1 commit=$2 identity=$3

git config gpg.format x509
git config gpg.x509.program gitsign
git config user.name "Conn3x release"
git config user.email 41898282+github-actions[bot]@users.noreply.github.com
git tag -s -m "$tag" "$tag" "$commit"
# Rekor's search index can lag the write by a minute or more, and verify
# looks the entry up there, so a signature made a second ago may not be
# found yet ("could not find matching tlog entry"). Retry for about two
# minutes; any other failure, or the same one after that, still stops
# the release before the tag is pushed.
for try in 1 2 3 4 5 6 7 8; do
  if out=$(gitsign verify-tag \
    --certificate-identity-regexp "$identity" \
    --certificate-oidc-issuer https://token.actions.githubusercontent.com \
    "$tag" 2>&1); then
    printf '%s\n' "$out"
    exit 0
  fi
  printf '%s\n' "$out" >&2
  case $out in
    *"could not find matching tlog entry"*) [ "$try" -lt 8 ] && sleep 15 ;;
    *) exit 1 ;;
  esac
done
exit 1
