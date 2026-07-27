#!/usr/bin/env bash
set -euo pipefail

lockfile=${1:-Cargo.lock}
awk '
    $0 == "[[package]]" {
        root_package = 0
    }
    $0 == "name = \"codex-ssh-bridge\"" {
        root_package = 1
    }
    root_package && /^version = / {
        skipped += 1
        next
    }
    {
        print
    }
    END {
        if (skipped != 1) {
            exit 2
        }
    }
' "$lockfile" | sha256sum | cut -d ' ' -f 1
