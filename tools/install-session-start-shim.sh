#!/usr/bin/env bash
# install-session-start-shim.sh — install a self-resolving session-start shim.
#
# Installs ~/.auditooor/bin/auditooor-session-start.sh so git hooks, Codex, and
# Claude can invoke the current workspace's session-start runner without
# hardcoding an old worktree path.
#
# Usage:
#   bash tools/install-session-start-shim.sh install
#   bash tools/install-session-start-shim.sh check
#   bash tools/install-session-start-shim.sh uninstall

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
BIN_DIR="${AUDITOOOR_BIN_DIR:-$HOME/.auditooor/bin}"
TARGET="$BIN_DIR/auditooor-session-start.sh"

_render_shim() {
cat <<EOF
#!/usr/bin/env bash
# auditooor-session-start.sh — generated shim for current-workspace session start.
#
# This shim resolves the live workspace at runtime, then delegates to the repo-
# local tools/auditooor-session-start.sh for that workspace. It deliberately
# avoids hardcoding a single worktree path so stale shims self-heal.

set -euo pipefail

_resolve_target() {
    local candidate

    if [[ -n "\${AUDITOOOR_SESSION_START_SH:-}" ]] && [[ -x "\${AUDITOOOR_SESSION_START_SH:-}" ]]; then
        printf '%s\n' "\${AUDITOOOR_SESSION_START_SH}"
        return 0
    fi

    if command -v git >/dev/null 2>&1; then
        local ws
        ws="\$(git rev-parse --show-toplevel 2>/dev/null || true)"
        if [[ -n "\$ws" ]] && [[ -x "\$ws/tools/auditooor-session-start.sh" ]]; then
            printf '%s\n' "\$ws/tools/auditooor-session-start.sh"
            return 0
        fi
    fi

    for candidate in \
        "${REPO_ROOT}/tools/auditooor-session-start.sh" \
        "/Users/wolf/auditooor-mcp/tools/auditooor-session-start.sh"
    do
        if [[ -x "\$candidate" ]]; then
            printf '%s\n' "\$candidate"
            return 0
        fi
    done

    return 1
}

TARGET="\$(_resolve_target)" || {
    echo "[auditooor-session-start-shim] ERROR: could not resolve a session-start runner." >&2
    echo "[auditooor-session-start-shim] Run: bash ${REPO_ROOT}/tools/install-session-start-shim.sh install" >&2
    exit 1
}

exec bash "\$TARGET" "\$@"
EOF
}

_install() {
    mkdir -p "$BIN_DIR"
    _render_shim > "$TARGET"
    chmod 755 "$TARGET"
    echo "[install-session-start-shim] Installed: $TARGET"
}

_check() {
    if [[ ! -f "$TARGET" ]]; then
        echo "[install-session-start-shim] MISSING: $TARGET"
        return 1
    fi
    if grep -q "self-heal" "$TARGET" 2>/dev/null || grep -q "generated shim" "$TARGET" 2>/dev/null; then
        echo "[install-session-start-shim] INSTALLED: $TARGET"
        return 0
    fi
    echo "[install-session-start-shim] PRESENT: $TARGET (foreign or unmanaged)"
    return 1
}

_uninstall() {
    if [[ -f "$TARGET" ]]; then
        rm -f "$TARGET"
        echo "[install-session-start-shim] Removed: $TARGET"
    else
        echo "[install-session-start-shim] Not present: $TARGET"
    fi
}

case "${1:-install}" in
    install)
        _install
        ;;
    check)
        _check
        ;;
    uninstall)
        _uninstall
        ;;
    --help|-h|help)
        sed -n '1,40p' "$0"
        ;;
    *)
        echo "Usage: bash tools/install-session-start-shim.sh [install|check|uninstall|--help]" >&2
        exit 1
        ;;
esac
