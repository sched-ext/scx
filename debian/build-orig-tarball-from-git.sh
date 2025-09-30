#!/bin/bash
#
# Produce an orig tarball that can be used to build a deb package.

if [[ $(git --no-optional-locks status -uno --porcelain) ]]; then
    echo "ERROR: git repository is not clean"
    exit 1
fi

# Stop on error
set -e

# Clean repo
git clean -xdf

# Produce source package (including an orig tarball)
version=$(dpkg-parsechangelog -SVersion | cut -d- -f1)
mkdir -p deb
git archive --prefix=scx-${version}/ -o deb/scx_${version}.orig.tar.gz HEAD

# Show the orig tarball.
echo "Done."
ls -ltrah deb/*.tar.gz
