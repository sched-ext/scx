#!/usr/bin/env bash
# Retired experiment harness. It used an internal privilege wrapper and manual
# mutation environment, so it cannot produce attributable owner-user evidence.
set -Eeuo pipefail

echo "error: retired non-canonical harness; use /home/ritz/Documents/Repo/scx/cakebench" >&2
echo "use cakebench artifact and native-pair; see scheds/rust/scx_cake/bench/README.md" >&2
exit 2
