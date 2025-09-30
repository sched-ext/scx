#!/bin/bash
#
# Produce a deb source package that can be uploaded to a Debian/Ubuntu builder.

if [[ $(git --no-optional-locks status -uno --porcelain) ]]; then
    echo "ERROR: git repository is not clean"
    exit 1
fi

# Stop on error
set -e

# Create upstream tag (required by gbp)
version=$(dpkg-parsechangelog -SVersion | cut -d- -f1)
git tag -f upstream/${version} HEAD~1

# Clean-up binary artifacts
cd libbpf
rm -f assets/*
rm -f fuzz/bpf-object-fuzzer_seed_corpus.zip
cd -

# Produce source package (including an orig tarball)
rm -rf build
cd libbpf
git clean -xdf
cd -
git clean -xdf
gbp buildpackage --git-ignore-branch -S -sa --lintian-opts --no-lintian
