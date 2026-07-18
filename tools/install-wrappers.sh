#!/usr/bin/env bash
# install-wrappers.sh — install MCP-gated PATH-shim wrappers.
# Lane 7 of MCP harness review (PR #658) commit 8.
# Wave-6 E-2: added freshness-wiring sanity check + install-default-on subcommand.
#
# Symlinks tools/auditooor-<name>-wrapper.sh into ~/.auditooor/bin/<name> so
# git/gh (and future codex/kimi) calls auto-route through MCP gating when
# ~/.auditooor/bin is prepended to $PATH.
#
# Usage:
#   bash tools/install-wrappers.sh install                    # install (idempotent)
#   bash tools/install-wrappers.sh install --auto-add-to-path # install + add to shell rc
#   bash tools/install-wrappers.sh uninstall                  # remove symlinks
#   bash tools/install-wrappers.sh check                      # verify install state
#   bash tools/install-wrappers.sh check-path                 # report PATH inclusion
#   bash tools/install-wrappers.sh check-freshness-wiring     # verify each wrapper has freshness gate
#
# Backward compatibility:
#   Existing Wave-3/Wave-4 callers that pass no freshness token can use
#   AUDITOOOR_NO_FRESHNESS_CHECK=1 to skip the freshness gate while keeping
#   all other token-presence checks in place.

set -euo pipefail

AUDITOOOR_BIN="${AUDITOOOR_BIN_DIR:-$HOME/.auditooor/bin}"
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
ACTION="${1:-install}"

# Wave-6 E-2: freshness gate sentinel string — present in every updated wrapper
FRESHNESS_GATE_SENTINEL="Wave-6 E-2: MCP recall freshness gate"
FINALIZATION_GATE_SENTINEL="Loop-finalization gate"

mkdir -p "$AUDITOOOR_BIN"

declare -a WRAPPERS
for w in "$SCRIPT_DIR"/auditooor-*-wrapper.sh; do
  [ -f "$w" ] || continue
  WRAPPERS+=("$w")
done

if [ ${#WRAPPERS[@]} -eq 0 ]; then
  echo "[install-wrappers] no auditooor-*-wrapper.sh files in $SCRIPT_DIR" >&2
  exit 1
fi

# ---------------------------------------------------------------------------
# Helper: detect shell rc file
# ---------------------------------------------------------------------------
_detect_shell_rc() {
  case "${SHELL:-}" in
    */zsh)  echo "$HOME/.zshrc" ;;
    */bash) echo "$HOME/.bashrc" ;;
    *)
      # Fallback: prefer .zshrc if it exists, else .bashrc
      if [ -f "$HOME/.zshrc" ]; then
        echo "$HOME/.zshrc"
      else
        echo "$HOME/.bashrc"
      fi
      ;;
  esac
}

# ---------------------------------------------------------------------------
# Helper: install symlinks (core logic)
# ---------------------------------------------------------------------------
_do_install() {
  for w in "${WRAPPERS[@]}"; do
    base="$(basename "$w")"
    # auditooor-git-wrapper.sh -> git
    name="${base#auditooor-}"; name="${name%-wrapper.sh}"
    target="$AUDITOOOR_BIN/$name"
    if [ -L "$target" ] && [ "$(readlink "$target")" = "$w" ]; then
      echo "  [unchanged] $target"
    else
      ln -sf "$w" "$target"
      chmod +x "$w"
      echo "  [installed] $target -> $w"
    fi
  done

  # Wave-6 E-2: sanity check that every installed wrapper has freshness gate
  echo ""
  echo "[install-wrappers] Freshness-wiring check:"
  local warn=0
  for w in "${WRAPPERS[@]}"; do
    base="$(basename "$w")"
    if grep -q "$FRESHNESS_GATE_SENTINEL" "$w" 2>/dev/null; then
      echo "  [OK]      freshness gate present in $base"
    else
      echo "  [WARN]    freshness gate MISSING in $base — re-run: bash $SCRIPT_DIR/install-wrappers.sh install" >&2
      warn=1
    fi
    if [ "$base" = "auditooor-codex-wrapper.sh" ]; then
      if grep -q "$FINALIZATION_GATE_SENTINEL" "$w" 2>/dev/null; then
        echo "  [OK]      finalization gate present in $base"
      else
        echo "  [WARN]    finalization gate MISSING in $base — re-run: bash $SCRIPT_DIR/install-wrappers.sh install" >&2
        warn=1
      fi
    fi
  done
  if [ "$warn" -eq 1 ]; then
    echo "[install-wrappers] WARNING: some wrappers lack the Wave-6 E-2 freshness gate." >&2
    echo "[install-wrappers] Run 'bash $SCRIPT_DIR/install-wrappers.sh install' to refresh." >&2
  fi
}

case "$ACTION" in
  install|"")
    AUTO_ADD_PATH=0
    if [ "${2:-}" = "--auto-add-to-path" ]; then
      AUTO_ADD_PATH=1
    fi

    _do_install

    cat <<EOF

[install-wrappers] Done. Issue session token first:

  python3 $SCRIPT_DIR/auditooor_mcp_token.py issue --workspace \$PWD
  export AUDITOOOR_MCP_SESSION_TOKEN=<output>

Or override (audit-logged):  export AUDITOOOR_MCP_REQUIRED=0
EOF

    if [ "$AUTO_ADD_PATH" -eq 1 ]; then
      RC="$(_detect_shell_rc)"
      PATH_EXPORT="export PATH=\"\$HOME/.auditooor/bin:\$PATH\""
      if grep -qF "$HOME/.auditooor/bin" "$RC" 2>/dev/null; then
        echo "[install-wrappers] PATH entry already present in $RC"
      else
        printf '\n# auditooor Wave-6 E-2: MCP-gated wrappers\n%s\n' "$PATH_EXPORT" >> "$RC"
        echo "[install-wrappers] Added PATH entry to $RC"
        echo "[install-wrappers] Reload shell or run: source $RC"
      fi
    else
      echo ""
      echo "[install-wrappers] To add to PATH automatically, run:"
      echo "  bash $SCRIPT_DIR/install-wrappers.sh install --auto-add-to-path"
      echo ""
      echo "[install-wrappers] Or add manually to ~/.zshrc or ~/.bashrc:"
      echo "  export PATH=\"\$HOME/.auditooor/bin:\$PATH\""
    fi
    ;;

  uninstall)
    for w in "${WRAPPERS[@]}"; do
      base="$(basename "$w")"
      name="${base#auditooor-}"; name="${name%-wrapper.sh}"
      target="$AUDITOOOR_BIN/$name"
      if [ -L "$target" ]; then
        rm "$target"
        echo "  [removed] $target"
      fi
    done
    ;;

  check)
    fail=0
    for w in "${WRAPPERS[@]}"; do
      base="$(basename "$w")"
      name="${base#auditooor-}"; name="${name%-wrapper.sh}"
      target="$AUDITOOOR_BIN/$name"
      if [ -L "$target" ] && [ "$(readlink "$target")" = "$w" ]; then
        echo "  [OK]      $target"
      else
        echo "  [MISSING] $target" >&2
        fail=1
      fi
    done
    # Check PATH
    case ":$PATH:" in
      *":$AUDITOOOR_BIN:"*) echo "  [OK]      \$AUDITOOOR_BIN in PATH" ;;
      *) echo "  [WARN]    \$AUDITOOOR_BIN not in PATH" >&2; fail=1 ;;
    esac
    exit $fail
    ;;

  check-path)
    case ":$PATH:" in
      *":$AUDITOOOR_BIN:"*)
        echo "[install-wrappers] PATH includes $AUDITOOOR_BIN"
        exit 0
        ;;
      *)
        echo "[install-wrappers] PATH does not include $AUDITOOOR_BIN"
        echo "[install-wrappers] Add to shell rc: export PATH=\"\$HOME/.auditooor/bin:\$PATH\""
        echo "[install-wrappers] Or auto-add: bash $SCRIPT_DIR/install-wrappers.sh install --auto-add-to-path"
        exit 1
        ;;
    esac
    ;;

  check-freshness-wiring)
    fail=0
    for w in "${WRAPPERS[@]}"; do
      base="$(basename "$w")"
      if grep -q "$FRESHNESS_GATE_SENTINEL" "$w" 2>/dev/null; then
        echo "  [OK]      freshness gate present in $base"
      else
        echo "  [MISSING] freshness gate in $base — needs reinstall with updated wrapper" >&2
        fail=1
      fi
      if [ "$base" = "auditooor-codex-wrapper.sh" ]; then
        if grep -q "$FINALIZATION_GATE_SENTINEL" "$w" 2>/dev/null; then
          echo "  [OK]      finalization gate present in $base"
        else
          echo "  [MISSING] finalization gate in $base — needs reinstall with updated wrapper" >&2
          fail=1
        fi
      fi
    done
    if [ "$fail" -eq 0 ]; then
      echo "[install-wrappers] All wrappers have Wave-6 E-2 freshness gate wired."
    else
      echo "[install-wrappers] Some wrappers need update. Run: bash $SCRIPT_DIR/install-wrappers.sh install" >&2
    fi
    exit $fail
    ;;

  *)
    echo "Usage: $0 [install|install --auto-add-to-path|uninstall|check|check-path|check-freshness-wiring]" >&2
    exit 2
    ;;
esac
