#!/usr/bin/env bash
# solodit-shell-export-helper.sh
# Rule 37: this script does NOT emit corpus records; not subject to verification_tier.
#
# Reads SOLODIT_API_KEY from ~/.claude.json (mcpServers.solodit.env) and either:
#   --detect        Print masked key preview + confirm found (default, no side effects)
#   --print-only    Alias for --detect
#   --reveal        Print full key as export line (use in non-terminal / piped context)
#   --append-zshrc  Append export line to ~/.zshrc if key not already present (idempotent)
#
# Does NOT modify ~/.zshrc unless --append-zshrc is explicitly passed.
# Does NOT print the full key in terminal unless --reveal is passed.

set -euo pipefail

# ---------- helpers ----------

die() { echo "ERROR: $*" >&2; exit 1; }

extract_key_python() {
  python3 - <<'PYEOF'
import json, sys, pathlib
p = pathlib.Path.home() / ".claude.json"
if not p.exists():
    sys.exit(1)
try:
    d = json.loads(p.read_text())
    key = d.get("mcpServers", {}).get("solodit", {}).get("env", {}).get("SOLODIT_API_KEY", "")
    if not key:
        sys.exit(1)
    print(key, end="")
except Exception:
    sys.exit(1)
PYEOF
}

mask_key() {
  local key="$1"
  local prefix="${key:0:6}"
  local suffix="${key: -4}"
  echo "${prefix}***...${suffix}"
}

# ---------- main ----------

MODE="detect"

for arg in "$@"; do
  case "$arg" in
    --detect|--print-only) MODE="detect" ;;
    --reveal)              MODE="reveal" ;;
    --append-zshrc)        MODE="append" ;;
    --help|-h)
      echo "Usage: $0 [--detect|--print-only|--reveal|--append-zshrc]"
      echo "  --detect        Show masked key preview (default, no side effects)"
      echo "  --print-only    Alias for --detect"
      echo "  --reveal        Print full export line to stdout"
      echo "  --append-zshrc  Append export to ~/.zshrc (idempotent)"
      exit 0
      ;;
    *) die "Unknown argument: $arg (run with --help)" ;;
  esac
done

KEY="$(extract_key_python)" || die "SOLODIT_API_KEY not found in ~/.claude.json at mcpServers.solodit.env.SOLODIT_API_KEY"

EXPORT_LINE="export SOLODIT_API_KEY='${KEY}'"

case "$MODE" in
  detect)
    MASKED="$(mask_key "$KEY")"
    echo "[solodit-shell-export-helper] Key found: ${MASKED}"
    echo "[solodit-shell-export-helper] Run with --reveal to print full export line, or --append-zshrc to add to ~/.zshrc"
    ;;

  reveal)
    echo "$EXPORT_LINE"
    ;;

  append)
    ZSHRC="${HOME}/.zshrc"
    if grep -qF "SOLODIT_API_KEY" "$ZSHRC" 2>/dev/null; then
      echo "[solodit-shell-export-helper] SOLODIT_API_KEY already present in ${ZSHRC} - no change made (idempotent)."
    else
      TIMESTAMP="$(date -u '+%Y-%m-%dT%H:%M:%SZ')"
      printf '\n# solodit-shell-export-helper appended %s\n%s\n' "$TIMESTAMP" "$EXPORT_LINE" >> "$ZSHRC"
      echo "[solodit-shell-export-helper] Appended to ${ZSHRC}."
      echo "[solodit-shell-export-helper] Revert: remove the 3-line block at the bottom of ${ZSHRC} that contains SOLODIT_API_KEY."
      echo "[solodit-shell-export-helper] Reload: source ${ZSHRC}"
    fi
    ;;
esac
