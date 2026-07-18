#!/usr/bin/env bash
# sessionend-run-privacy-audit.sh — SessionEnd hook: run privacy-audit and
# merge its result into the existing sessionend_packet.json under the key
# "privacy_audit".
#
# PR #658 Lane 7 — Tier-B #11 deliverable.
#
# Designed to be chained after (or alongside) tools/hooks/sessionend-forever-loop-packet.sh.
# It reads the packet written by that hook, adds/overwrites the "privacy_audit"
# key with summary metadata from memory-privacy-audit.py, then atomically
# replaces the packet.
#
# Workspace resolution:
#   1. $CLAUDE_PROJECT_DIR  (set by Claude Code harness on SessionEnd)
#   2. $AUDITOOOR_WS        (manual override)
#   3. pwd
#
# Requirements:
#   - python3 in PATH
#   - tools/memory-privacy-audit.py exists in REPO_ROOT
#
# Exit 0 always — never disrupts session teardown.

set -uo pipefail

# ---------------------------------------------------------------------------
# Resolve workspace + repo root
# ---------------------------------------------------------------------------
if [[ -n "${CLAUDE_PROJECT_DIR:-}" ]]; then
    WS="$CLAUDE_PROJECT_DIR"
elif [[ -n "${AUDITOOOR_WS:-}" ]]; then
    WS="$AUDITOOOR_WS"
else
    WS="$(pwd)"
fi
WS="$(cd "$WS" 2>/dev/null && pwd || echo "$WS")"

# For auditooor worktrees the script lives at <repo>/scripts/; repo root = parent
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" 2>/dev/null && pwd || echo "$WS/scripts")"
REPO_ROOT="$(cd "${SCRIPT_DIR}/.." 2>/dev/null && pwd || echo "$WS")"

PRIVACY_AUDIT="${REPO_ROOT}/tools/memory-privacy-audit.py"
AUDITOOOR_DIR="${WS}/.auditooor"
PACKET_PATH="${AUDITOOOR_DIR}/sessionend_packet.json"
TMP_AUDIT_JSON="${AUDITOOOR_DIR}/privacy_audit_session_tmp.$$.json"
VAULT_DIR="${REPO_ROOT}/obsidian-vault"
WHITELIST="${REPO_ROOT}/reports/privacy_audit_whitelist.yaml"

# ---------------------------------------------------------------------------
# Guard: tool + vault must exist
# ---------------------------------------------------------------------------
if [[ ! -f "$PRIVACY_AUDIT" ]]; then
    exit 0
fi
if [[ ! -d "$VAULT_DIR" ]]; then
    # No vault present in this clone — skip silently
    exit 0
fi
if ! command -v python3 >/dev/null 2>&1; then
    exit 0
fi

mkdir -p "$AUDITOOOR_DIR"

# ---------------------------------------------------------------------------
# Run privacy audit → JSON
# ---------------------------------------------------------------------------
AUDIT_ARGS=(
    --vault "$VAULT_DIR"
    --out-json "$TMP_AUDIT_JSON"
    --out-md /dev/null
)
if [[ -f "$WHITELIST" ]]; then
    AUDIT_ARGS+=(--whitelist "$WHITELIST")
fi

# Run audit; capture exit code but do not propagate
python3 "$PRIVACY_AUDIT" "${AUDIT_ARGS[@]}" >/dev/null 2>&1 || true

# ---------------------------------------------------------------------------
# Read audit result summary (without jq dependency)
# ---------------------------------------------------------------------------
AUDIT_TOTAL=0
AUDIT_HIGH=0
AUDIT_GENERATED_AT=""

if [[ -f "$TMP_AUDIT_JSON" ]]; then
    AUDIT_TOTAL="$(python3 -c "
import json, sys
try:
    d = json.load(open('${TMP_AUDIT_JSON}'))
    print(d.get('total_findings', 0))
except Exception:
    print(0)
" 2>/dev/null || echo 0)"

    AUDIT_HIGH="$(python3 -c "
import json, sys
try:
    d = json.load(open('${TMP_AUDIT_JSON}'))
    highs = [f for f in d.get('findings', []) if f.get('severity') in ('HIGH','CRITICAL')]
    print(len(highs))
except Exception:
    print(0)
" 2>/dev/null || echo 0)"

    AUDIT_GENERATED_AT="$(python3 -c "
import json
try:
    d = json.load(open('${TMP_AUDIT_JSON}'))
    print(d.get('generated_at', ''))
except Exception:
    print('')
" 2>/dev/null || echo '')"
fi

# Cleanup temp audit JSON
rm -f "$TMP_AUDIT_JSON"

# ---------------------------------------------------------------------------
# Merge into existing sessionend_packet.json (or create minimal packet)
# ---------------------------------------------------------------------------
TIMESTAMP="$(date -u '+%Y-%m-%dT%H:%M:%SZ' 2>/dev/null || echo 'UNKNOWN')"

python3 - <<PYEOF
import json, os, sys

packet_path = "${PACKET_PATH}"
audit_total = ${AUDIT_TOTAL}
audit_high  = ${AUDIT_HIGH}
audit_ts    = "${AUDIT_GENERATED_AT}" or "${TIMESTAMP}"

privacy_block = {
    "run_at": audit_ts,
    "total_findings": audit_total,
    "high_critical_count": audit_high,
    "status": "CLEAN" if audit_high == 0 else "NEEDS_REMEDIATION",
    "note": (
        "Vault clean — no HIGH/CRITICAL findings." if audit_high == 0
        else f"{audit_high} HIGH/CRITICAL finding(s) detected. Run: make memory-privacy-audit-quarantine"
    ),
}

# Read existing packet if present
existing = {}
if os.path.exists(packet_path):
    try:
        with open(packet_path) as f:
            existing = json.load(f)
    except Exception:
        pass

# Merge: add/overwrite privacy_audit key
existing["privacy_audit"] = privacy_block

# Atomic write
tmp = packet_path + ".privacy.tmp.$$"
try:
    with open(tmp, "w") as f:
        json.dump(existing, f, indent=2)
    os.replace(tmp, packet_path)
except Exception as e:
    print(f"[sessionend-privacy-audit] WARNING: could not write packet: {e}", file=sys.stderr)
    if os.path.exists(tmp):
        os.remove(tmp)
PYEOF

exit 0
