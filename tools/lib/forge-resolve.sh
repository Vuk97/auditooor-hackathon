#!/usr/bin/env bash
# forge-resolve.sh — Canonical forge binary discovery for auditooor tools.
#
# Source this file in bash scripts that need forge:
#   source "$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/../lib/forge-resolve.sh"
#
# After sourcing, $FORGE_BIN is set to the correct forge binary.
# If forge cannot be found, prints error to stderr and returns 1.
#
# Resolution order:
#   1. $FORGE_BIN (if already set and executable)
#   2. ~/.foundry/bin/forge (canonical install location)
#   3. $(command -v forge) from PATH
#   4. /opt/foundry/bin/forge (Linux common location)
#
# Validation: runs `forge --version` and checks that `forge build --help`
# succeeds (catches fake/broken forge binaries).

_discover_forge() {
    local candidates=()

    # 1. Environment override
    if [ -n "${FORGE_BIN:-}" ] && [ -x "$FORGE_BIN" ]; then
        candidates+=("$FORGE_BIN")
    fi

    # 2. Canonical homebrew/curl install location
    if [ -x "$HOME/.foundry/bin/forge" ]; then
        candidates+=("$HOME/.foundry/bin/forge")
    fi

    # 3. PATH
    local path_forge
    path_forge=$(command -v forge 2>/dev/null || true)
    if [ -n "$path_forge" ] && [ -x "$path_forge" ]; then
        candidates+=("$path_forge")
    fi

    # 4. Linux common location
    if [ -x "/opt/foundry/bin/forge" ]; then
        candidates+=("/opt/foundry/bin/forge")
    fi

    # Test each candidate
    for candidate in "${candidates[@]}"; do
        if [ ! -x "$candidate" ]; then
            continue
        fi
        # Validate: must support `forge build --help`
        if "$candidate" build --help >/dev/null 2>&1; then
            echo "$candidate"
            return 0
        fi
    done

    return 1
}

FORGE_BIN=$(_discover_forge)
if [ -z "$FORGE_BIN" ]; then
    echo "[forge-resolve] ERROR: No working forge binary found." >&2
    echo "  Install: curl -L https://foundry.paradigm.xyz | bash" >&2
    echo "  Then: foundryup" >&2
    return 1 2>/dev/null || exit 1
fi

export FORGE_BIN
# Also prepend to PATH so child processes (Slither, forge) find the right one
export PATH="$(dirname "$FORGE_BIN"):$PATH"
