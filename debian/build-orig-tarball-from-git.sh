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

# Vendor Rust crates
debian/rules fetch
# Remove .orig references from checksum files (quilt can leave backups)
python3 debian/sanitize-vendor-checksums.py
find vendor -name '*.orig' -delete 2>/dev/null || true
git add -f vendor
git commit -s -a -m "DROP THIS: Rust crates"

# Produce source package (including an orig tarball)
version=$(dpkg-parsechangelog -SVersion | cut -d- -f1)
mkdir deb
git archive --prefix=scx-${version}/ -o deb/scx_${version}.orig.tar.gz HEAD

# Show the orig tarball.
echo "Done."
ls -ltrah deb/*.tar.gz
