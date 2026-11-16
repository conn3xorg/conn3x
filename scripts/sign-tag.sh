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
gitsign verify-tag \
  --certificate-identity-regexp "$identity" \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com \
  "$tag"
