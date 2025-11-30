#!/usr/bin/bash

cgid="$1"
if [ -z "$cgid" ]; then
    echo "Usage: cgpath <cgid>" >&2
    exit 1
fi

find /sys/fs/cgroup -type d -exec stat -c '%i %n' {} \; \
    | awk -v id="$cgid" '$1 == id {print $2}'
