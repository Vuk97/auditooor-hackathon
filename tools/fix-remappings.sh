#!/usr/bin/env bash
# fix-remappings.sh — R79 T5: rewrite `./`-style remappings to absolute paths.
#
# Background: Slither / CryticCompile treats `@foo/=./` as `@foo/=/` (absolute
# root `/`), producing bogus `Unknown file: /src/...` errors on every scan.
# The upstream fix is pending, so we pre-process the workspace's
# remappings.txt and foundry.toml before every scan.
#
# Usage:
#   bash tools/fix-remappings.sh <workspace>
#
# Behavior:
#   1. Read <workspace>/remappings.txt + <workspace>/foundry.toml remappings.
#   2. For any line matching `^@<name>/=\./?$` or `^<name>/=\./?$`, replace
#      with `<name>/=<abs-path-to-workspace>/`.
#   3. Write back in place. Backup to .bak on first run.
#
# Idempotent: running twice produces no further changes.

set -u
WS="${1:-}"
[ -z "$WS" ] || [ ! -d "$WS" ] && { echo "usage: $0 <workspace>" >&2; exit 1; }

WS_ABS=$(cd "$WS" && pwd)

_fix_file() {
    local f="$1"
    [ -f "$f" ] || return 0
    # Only rewrite lines that map to `.` or `./` — leave other lines alone.
    if grep -qE '=[[:space:]]*\./?[[:space:]]*$' "$f" 2>/dev/null; then
        [ ! -f "${f}.bak" ] && cp "$f" "${f}.bak"
        # Portable sed — BSD sed requires empty arg after -i on macOS.
        # Replace the RHS `./` (optionally trailing) with the absolute workspace path
        # Use | as delimiter to avoid escaping the workspace path's slashes.
        case "$(uname -s)" in
            Darwin*) sed -i '' -E "s|=[[:space:]]*\./?[[:space:]]*\$|=${WS_ABS}/|g" "$f" ;;
            *)       sed -i    -E "s|=[[:space:]]*\./?[[:space:]]*\$|=${WS_ABS}/|g" "$f" ;;
        esac
        echo "[fix-remappings] rewrote ./ → $WS_ABS/ in $f"
    fi
}

# Top-level workspace
_fix_file "$WS/remappings.txt"

# Foundry remappings embedded in foundry.toml — check for `remappings = [...]`
if [ -f "$WS/foundry.toml" ]; then
    if grep -qE '=["'"'"']\./?["'"'"']' "$WS/foundry.toml" 2>/dev/null; then
        [ ! -f "$WS/foundry.toml.bak" ] && cp "$WS/foundry.toml" "$WS/foundry.toml.bak"
        case "$(uname -s)" in
            Darwin*) sed -i '' -E "s|=([\"'])\./?\1|=\1${WS_ABS}/\1|g" "$WS/foundry.toml" ;;
            *)       sed -i    -E "s|=([\"'])\./?\1|=\1${WS_ABS}/\1|g" "$WS/foundry.toml" ;;
        esac
        echo "[fix-remappings] rewrote ./ → $WS_ABS/ in foundry.toml"
    fi
fi

# Nested foundry workspaces under src/<repo>/
while IFS= read -r nested; do
    _fix_file "$(dirname "$nested")/remappings.txt"
    if [ -f "$nested" ] && grep -qE '=["'"'"']\./?["'"'"']' "$nested" 2>/dev/null; then
        [ ! -f "${nested}.bak" ] && cp "$nested" "${nested}.bak"
        case "$(uname -s)" in
            Darwin*) sed -i '' -E "s|=([\"'])\./?\1|=\1$(dirname "$nested")/\1|g" "$nested" ;;
            *)       sed -i    -E "s|=([\"'])\./?\1|=\1$(dirname "$nested")/\1|g" "$nested" ;;
        esac
        echo "[fix-remappings] rewrote ./ in $nested"
    fi
done < <(find "$WS/src" -name "foundry.toml" 2>/dev/null | head -5)

echo "[fix-remappings] done"
