#!/usr/bin/env bash
# deep-engine-resolve.sh - Canonical deep-engine binary discovery for the
# auditooor toolchain (halmos / medusa / echidna).
#
# Source this file in a runner that needs a deep-engine binary:
#   source "$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/lib/deep-engine-resolve.sh"
#   if resolve_deep_engine halmos; then
#       # $DEEP_ENGINE_BIN is set to an executable path
#   fi
#
# Resolution order (first hit wins):
#   1. $AUDITOOOR_DEEP_BIN_<ENGINE> env override (if set and executable)
#   2. tools/deep-engine-bin/<engine> - the hermetic provisioned location
#      written by tools/provision-deep-engines.sh
#   3. $(command -v <engine>) from PATH
#
# If no binary is found, returns 1 and leaves $DEEP_ENGINE_BIN empty. This
# is NOT an error: the caller (the runner) is expected to fall back to its
# graceful tool-unavailable skip path so offline / un-provisioned
# environments keep exiting 0 with a skip artifact (no regression).

# Repo-root-anchored hermetic bin dir. BASH_SOURCE[0] is .../tools/lib/...
_DEEP_ENGINE_LIB_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
DEEP_ENGINE_BIN_DIR="${AUDITOOOR_DEEP_BIN_DIR:-$(cd "$_DEEP_ENGINE_LIB_DIR/.." && pwd)/deep-engine-bin}"

# resolve_deep_engine <engine-name>
#   engine-name: halmos | medusa | echidna
# On success: returns 0, exports DEEP_ENGINE_BIN + DEEP_ENGINE_SOURCE.
# On failure: returns 1, DEEP_ENGINE_BIN="" and DEEP_ENGINE_SOURCE="none".
resolve_deep_engine() {
    local engine="$1"
    DEEP_ENGINE_BIN=""
    DEEP_ENGINE_SOURCE="none"

    # 1. Per-engine env override.
    local override_var
    override_var="AUDITOOOR_DEEP_BIN_$(printf '%s' "$engine" | tr '[:lower:]' '[:upper:]')"
    local override_val="${!override_var:-}"
    if [ -n "$override_val" ] && [ -x "$override_val" ]; then
        DEEP_ENGINE_BIN="$override_val"
        DEEP_ENGINE_SOURCE="env-override"
        return 0
    fi

    # 2. Hermetic provisioned location.
    if [ -x "$DEEP_ENGINE_BIN_DIR/$engine" ]; then
        DEEP_ENGINE_BIN="$DEEP_ENGINE_BIN_DIR/$engine"
        DEEP_ENGINE_SOURCE="provisioned"
        return 0
    fi

    # 3. PATH fallback (pre-existing behaviour).
    local path_bin
    if path_bin="$(command -v "$engine" 2>/dev/null)"; then
        DEEP_ENGINE_BIN="$path_bin"
        DEEP_ENGINE_SOURCE="path"
        return 0
    fi

    return 1
}

# deep_engine_available <engine-name>
#   Boolean helper for the Makefile / scripts: prints nothing, returns 0 if
#   the engine resolves, 1 otherwise. Mirrors `command -v <engine>` usage.
deep_engine_available() {
    resolve_deep_engine "$1" >/dev/null 2>&1
}
