#!/usr/bin/env bash
# Copyright (c) The Conn3x Authors
# SPDX-License-Identifier: MPL-2.0
#
# Builds the apt and dnf repositories that conn3xorg/packages serves on
# GitHub Pages, from the .deb and .rpm files of the latest releases (#684).
#
#   publish-packages.sh OUT TAG [TAG...]
#
# OUT is an empty directory to write the site into; each TAG is a release,
# newest first, whose packages are downloaded with gh. A TAG of the form
# OWNER/REPO@TAG is a release of another repository, such as
# conn3xorg/conn3x-ui@v0.4.0, so its packages share the repositories. The key that signs
# the repository metadata must already be in gpg's keyring, its ID in
# GPG_KEY_ID. The packages themselves are signed at build time (nfpms in
# .goreleaser.yaml).
#
# apt can't fetch a package from another host, so the .debs are copied into
# the site. The .rpms stay on GitHub Releases: the dnf metadata names them
# there through xml:base, so the site holds no RPMs at all.
set -euo pipefail

out=${1:?usage: publish-packages.sh OUT TAG [TAG...]}
shift
[ $# -gt 0 ] || { echo "name at least one release tag" >&2; exit 1; }
: "${GPG_KEY_ID:?set GPG_KEY_ID to the signing key}"
repo=${PACKAGES_SOURCE_REPO:-conn3xorg/conn3x}
site_url=${PACKAGES_SITE_URL:-https://conn3xorg.github.io/packages}

work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT
mkdir -p "$out/rpm"

# Each release's RPMs go under OWNER/REPO/releases/download/TAG, so one base
# URL, github.com, reaches every repository's.
for arg in "$@"; do
	from=$repo tag=$arg
	if [[ $arg == */*@* ]]; then
		from=${arg%@*} tag=${arg#*@}
	fi
	pool=$out/apt/pool/main/c/${from#*/}
	mkdir -p "$pool" "$work/rpm/$from/releases/download/$tag"
	gh release download "$tag" -R "$from" -p '*.deb' -D "$pool" --clobber
	gh release download "$tag" -R "$from" -p '*.rpm' -D "$work/rpm/$from/releases/download/$tag" --clobber
done

# apt: one suite, stable, with a Packages index per architecture, and a
# Release file signed both inline (InRelease) and detached (Release.gpg).
(
	cd "$out/apt"
	for arch in amd64 arm64; do
		dir=dists/stable/main/binary-$arch
		mkdir -p "$dir"
		apt-ftparchive --arch "$arch" packages pool > "$dir/Packages"
		gzip -9 -n -k -f "$dir/Packages"
	done
	apt-ftparchive \
		-o APT::FTPArchive::Release::Origin=Conn3x \
		-o APT::FTPArchive::Release::Label=Conn3x \
		-o APT::FTPArchive::Release::Suite=stable \
		-o APT::FTPArchive::Release::Codename=stable \
		-o "APT::FTPArchive::Release::Architectures=amd64 arm64" \
		-o APT::FTPArchive::Release::Components=main \
		release dists/stable > dists/stable/Release
	gpg --batch --yes --local-user "$GPG_KEY_ID" --clearsign -o dists/stable/InRelease dists/stable/Release
	gpg --batch --yes --local-user "$GPG_KEY_ID" --armor --detach-sign -o dists/stable/Release.gpg dists/stable/Release
)

# dnf: metadata over the downloaded RPMs, with every location under the
# release download URL, and repomd.xml signed for repo_gpgcheck.
createrepo_c --quiet --baseurl "https://github.com/" --outputdir "$out/rpm" "$work/rpm"
gpg --batch --yes --local-user "$GPG_KEY_ID" --armor --detach-sign -o "$out/rpm/repodata/repomd.xml.asc" "$out/rpm/repodata/repomd.xml"

gpg --batch --armor --export "$GPG_KEY_ID" > "$out/conn3x.asc"
cat > "$out/rpm/conn3x.repo" <<EOF
[conn3x]
name=Conn3x
baseurl=$site_url/rpm
enabled=1
gpgcheck=1
repo_gpgcheck=1
gpgkey=$site_url/conn3x.asc
EOF
cat > "$out/apt/conn3x.sources" <<EOF
Types: deb
URIs: $site_url/apt
Suites: stable
Components: main
Signed-By: /etc/apt/keyrings/conn3x.asc
EOF
touch "$out/.nojekyll"
