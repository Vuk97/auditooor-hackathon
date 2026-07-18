#!/usr/bin/env bash
# deploy-state-lookup.sh — deployment discovery + live-state handoff (Issue #139).
#
# Many high-value audit questions depend on deployment truth, not just source:
# role grants, proxy admins, adapter wiring, fee-module topology, pause/config
# flags, and deployed addresses. This wrapper searches likely workspace sources
# of deployment truth and also falls back to workspace notes/status/findings/
# staging evidence when deploy JSON is absent. Narrative evidence is ranked:
# direct line-level contract->address matches beat generic same-file address
# co-occurrence. When it can resolve a single address, it hands the live check
# off to tools/live-state-checker.py.
#
# Usage:
#   ./tools/deploy-state-lookup.sh <workspace> <search-term> [options]
#
# Examples:
#   ./tools/deploy-state-lookup.sh ~/audits/polymarket NegRiskFeeModule
#   ./tools/deploy-state-lookup.sh ~/audits/polymarket NegRiskAdapter \
#     --check-call "admins(address)(uint256)" --check-args 0xFEE_MODULE_ADDR \
#     --expect 0 --network polygon --rpc-url "$POLYGON_RPC_URL"
#   ./tools/deploy-state-lookup.sh ~/audits/centrifuge-v3 Root \
#     --address 0x... --slot 0x0 --network mainnet --json

set -uo pipefail

usage() {
  local code="${1:-2}"
  cat >&2 <<'USAGE'
usage: deploy-state-lookup.sh <workspace> <search-term> [options]
  --address 0x...                  use this address directly
  --network <name>                 network for live-state-checker.py (default: mainnet)
  --rpc-url <url>                  explicit RPC URL (alias: --chain)
  --check-call "fn(args)(rets)"    hand off a call check to live-state-checker.py
  --check-args "a,b,c"             positional args forwarded after --check-call
  --function "fn(args)(rets)"      legacy alias for --check-call
  --expect <value>                 expected substring/value for live check
  --slot <slot>                    hand off a storage slot check
  --balance-min <wei>              hand off a minimum balance check
  --dry-run                        plan the live check without hitting RPC
  --json                           emit structured JSON

Notes:
  - If no --address is given, the tool extracts candidate 0x addresses from
    deploy/config matches and will auto-hand off only when exactly one unique
    candidate is found.
  - Workspace narrative evidence prefers direct contract/address rows over
    generic same-file address co-occurrence.
  - If multiple candidate addresses are found, the tool reports them and leaves
    the final address choice to the operator/agent.
USAGE
  exit "$code"
}

case "${1:-}" in
  -h|--help) usage 0 ;;
esac

WS="${1:-}"
SEARCH_TERM="${2:-}"
[ -z "$WS" ] || [ ! -d "$WS" ] || [ -z "$SEARCH_TERM" ] && usage 2
shift 2

ADDRESS=""
NETWORK="mainnet"
RPC_URL=""
CHECK_CALL=""
CHECK_ARGS=""
EXPECT=""
SLOT=""
BALANCE_MIN=""
DRY_RUN=0
JSON=0

while [ $# -gt 0 ]; do
  case "$1" in
    --address) ADDRESS="${2:-}"; shift 2 ;;
    --network) NETWORK="${2:-}"; shift 2 ;;
    --rpc-url|--chain) RPC_URL="${2:-}"; shift 2 ;;
    --check-call|--function) CHECK_CALL="${2:-}"; shift 2 ;;
    --check-args) CHECK_ARGS="${2:-}"; shift 2 ;;
    --expect) EXPECT="${2:-}"; shift 2 ;;
    --slot) SLOT="${2:-}"; shift 2 ;;
    --balance-min) BALANCE_MIN="${2:-}"; shift 2 ;;
    --dry-run) DRY_RUN=1; shift ;;
    --json) JSON=1; shift ;;
    -h|--help) usage 0 ;;
    *) echo "[deploy-state-lookup] unknown arg: $1" >&2; usage 2 ;;
  esac
done

TMP_DIR=$(mktemp -d)
trap 'rm -rf "$TMP_DIR"' EXIT INT TERM

SRC_ROOT="$WS/src"
[ ! -d "$SRC_ROOT" ] && SRC_ROOT="$WS"

DEPLOY_GREP="$TMP_DIR/deploy_grep.txt"
DEPLOY_FILES="$TMP_DIR/deploy_files.txt"
SKILL_GREP="$TMP_DIR/skill_grep.txt"
WORKSPACE_GREP="$TMP_DIR/workspace_grep.txt"
SOURCE_GREP="$TMP_DIR/source_grep.txt"
ADDRS_RAW="$TMP_DIR/addrs_raw.txt"
ADDRS_UNIQ="$TMP_DIR/addrs_uniq.txt"
DIRECT_ADDRS_RAW="$TMP_DIR/direct_addrs_raw.txt"
DIRECT_ADDRS_UNIQ="$TMP_DIR/direct_addrs_uniq.txt"
CONTEXT_ADDRS_RAW="$TMP_DIR/context_addrs_raw.txt"
CONTEXT_ADDRS_UNIQ="$TMP_DIR/context_addrs_uniq.txt"
LIVE_JSON="$TMP_DIR/live.json"

touch "$DEPLOY_GREP" "$DEPLOY_FILES" "$SKILL_GREP" "$WORKSPACE_GREP" "$SOURCE_GREP" \
  "$ADDRS_RAW" "$ADDRS_UNIQ" "$DIRECT_ADDRS_RAW" "$DIRECT_ADDRS_UNIQ" "$CONTEXT_ADDRS_RAW" "$CONTEXT_ADDRS_UNIQ"

append_matches() {
  local path="$1"
  local out="$2"
  [ -e "$path" ] || return 0
  if [ -d "$path" ]; then
    grep -RniE --include='*.json' --include='*.yml' --include='*.yaml' --include='*.env' \
      --include='*.txt' --include='*.sol' --include='*.s.sol' "$SEARCH_TERM" "$path" \
      2>/dev/null >> "$out" || true
  else
    grep -niE "$SEARCH_TERM" "$path" 2>/dev/null >> "$out" || true
  fi
}

extract_addresses_from_file() {
  local file="$1"
  python3 - "$file" <<'PY'
import re
import sys
from pathlib import Path

text = Path(sys.argv[1]).read_text(errors="replace")
for addr in re.findall(r"0x[a-fA-F0-9]{40}", text):
    print(addr)
PY
}

classify_workspace_addresses() {
  local search_term="$1"
  local file="$2"
  python3 - "$search_term" "$file" <<'PY'
import re
import sys
from pathlib import Path

term = sys.argv[1].strip()
text = Path(sys.argv[2]).read_text(errors="replace")

addr_re = re.compile(r"0x[a-fA-F0-9]{40}")
term_re = re.compile(rf"\b{re.escape(term)}\b", re.IGNORECASE)
slug = re.sub(r"[^a-z0-9]+", "", term.lower())

def normalize(value: str) -> str:
    return re.sub(r"[^a-z0-9]+", "", value.lower())

for raw in text.splitlines():
    line = raw.strip()
    if not line or not term_re.search(line):
        continue
    addresses = addr_re.findall(line)
    if not addresses:
        continue
    direct = False
    if "|" in line:
        cells = [cell.strip(" `") for cell in line.split("|")]
        if len(cells) >= 3 and normalize(cells[2 if cells[0] == "" else 1]) == slug:
            direct = True
    if not direct:
        patterns = [
            rf"\b{re.escape(term)}\b[^0-9a-zA-Z]{{0,24}}(0x[a-fA-F0-9]{{40}})",
            rf"(0x[a-fA-F0-9]{{40}})[^0-9a-zA-Z]{{0,24}}\b{re.escape(term)}\b",
        ]
        for pattern in patterns:
            if re.search(pattern, line, re.IGNORECASE):
                direct = True
                break
    bucket = "DIRECT" if direct else "CONTEXT"
    for address in addresses:
        print(f"{bucket}\t{address}")
PY
}

# 1. Deploy scripts
for d in "$WS/script" "$WS/scripts"; do
  [ -d "$d" ] && append_matches "$d" "$DEPLOY_GREP"
done
while IFS= read -r d; do
  [ -n "$d" ] || continue
  append_matches "$d" "$DEPLOY_GREP"
done < <(find "$SRC_ROOT" -type d \( -name script -o -name scripts \) 2>/dev/null)

# 2. Deployments / env directories
for d in "$WS/deployments" "$WS/env" "$WS/env/latest"; do
  if [ -e "$d" ]; then
    append_matches "$d" "$DEPLOY_GREP"
    if [ -d "$d" ]; then
      grep -RliE "$SEARCH_TERM" "$d" 2>/dev/null >> "$DEPLOY_FILES" || true
    fi
  fi
done
while IFS= read -r d; do
  [ -n "$d" ] || continue
  append_matches "$d" "$DEPLOY_GREP"
  grep -RliE "$SEARCH_TERM" "$d" 2>/dev/null >> "$DEPLOY_FILES" || true
done < <(find "$SRC_ROOT" -type d \( -name deployments -o -name deploy \) 2>/dev/null)

# 3. Skill state
if [ -f "$WS/.skill_state.yaml" ]; then
  append_matches "$WS/.skill_state.yaml" "$SKILL_GREP"
fi

# 4. Workspace narrative evidence (status, findings, notes, staged drafts)
for p in "$WS/STATUS.md" "$WS/TODO.md" "$WS/FINDINGS.md" "$WS/notes" "$WS/submissions/staging"; do
  if [ -e "$p" ]; then
    append_matches "$p" "$WORKSPACE_GREP"
  fi
done

# 5. Source references
if [ -d "$SRC_ROOT" ]; then
  grep -RniE --include='*.sol' "\b${SEARCH_TERM}\b" "$SRC_ROOT" 2>/dev/null > "$SOURCE_GREP" || true
fi

# Candidate addresses from matches and matching files.
extract_addresses_from_file "$DEPLOY_GREP" >> "$ADDRS_RAW"
extract_addresses_from_file "$SKILL_GREP" >> "$ADDRS_RAW"
extract_addresses_from_file "$WORKSPACE_GREP" >> "$ADDRS_RAW"
classify_workspace_addresses "$SEARCH_TERM" "$WORKSPACE_GREP" > "$TMP_DIR/workspace_classified.txt"
awk -F '\t' '$1=="DIRECT"{print $2}' "$TMP_DIR/workspace_classified.txt" >> "$DIRECT_ADDRS_RAW" || true
awk -F '\t' '$1=="CONTEXT"{print $2}' "$TMP_DIR/workspace_classified.txt" >> "$CONTEXT_ADDRS_RAW" || true
while IFS= read -r file; do
  [ -n "$file" ] || continue
  [ -f "$file" ] || continue
  extract_addresses_from_file "$file" >> "$ADDRS_RAW"
done < "$DEPLOY_FILES"
sort -fu "$ADDRS_RAW" > "$ADDRS_UNIQ"
sort -fu "$DIRECT_ADDRS_RAW" > "$DIRECT_ADDRS_UNIQ"
sort -fu "$CONTEXT_ADDRS_RAW" > "$CONTEXT_ADDRS_UNIQ"

CANDIDATE_COUNT=$(grep -c . "$ADDRS_UNIQ" || true)
DIRECT_CANDIDATE_COUNT=$(grep -c . "$DIRECT_ADDRS_UNIQ" || true)
RESOLVED_ADDR="$ADDRESS"
if [ -z "$RESOLVED_ADDR" ] && [ "$DIRECT_CANDIDATE_COUNT" -eq 1 ]; then
  RESOLVED_ADDR=$(head -1 "$DIRECT_ADDRS_UNIQ")
elif [ -z "$RESOLVED_ADDR" ] && [ "$CANDIDATE_COUNT" -eq 1 ]; then
  RESOLVED_ADDR=$(head -1 "$ADDRS_UNIQ")
fi

LIVE_REQUESTED=0
[ -n "$CHECK_CALL" ] && LIVE_REQUESTED=1
[ -n "$SLOT" ] && LIVE_REQUESTED=1
[ -n "$BALANCE_MIN" ] && LIVE_REQUESTED=1

LIVE_RC=""
if [ "$LIVE_REQUESTED" -eq 1 ] && [ -n "$RESOLVED_ADDR" ]; then
  LIVE_CMD=(python3 tools/live-state-checker.py
    --workspace "$WS"
    --address "$RESOLVED_ADDR"
    --network "$NETWORK")
  [ -n "$RPC_URL" ] && LIVE_CMD+=(--rpc-url "$RPC_URL")
  [ -n "$CHECK_CALL" ] && LIVE_CMD+=(--call "$CHECK_CALL")
  [ -n "$CHECK_ARGS" ] && LIVE_CMD+=(--args "$CHECK_ARGS")
  [ -n "$EXPECT" ] && LIVE_CMD+=(--expect "$EXPECT")
  [ -n "$SLOT" ] && LIVE_CMD+=(--slot "$SLOT")
  [ -n "$BALANCE_MIN" ] && LIVE_CMD+=(--balance-min "$BALANCE_MIN")
  [ "$DRY_RUN" -eq 1 ] && LIVE_CMD+=(--dry-run)
  if [ "$JSON" -eq 1 ]; then
    LIVE_CMD+=(--json)
    "${LIVE_CMD[@]}" > "$LIVE_JSON"
    LIVE_RC=$?
  else
    "${LIVE_CMD[@]}"
    LIVE_RC=$?
  fi
fi

if [ "$JSON" -eq 1 ]; then
  python3 - "$WS" "$SEARCH_TERM" "$SRC_ROOT" "$DEPLOY_GREP" "$SKILL_GREP" "$WORKSPACE_GREP" "$SOURCE_GREP" \
    "$ADDRS_UNIQ" "$DIRECT_ADDRS_UNIQ" "$CONTEXT_ADDRS_UNIQ" "$RESOLVED_ADDR" "$NETWORK" "$RPC_URL" "$CHECK_CALL" "$CHECK_ARGS" "$EXPECT" "$SLOT" \
    "$BALANCE_MIN" "$DRY_RUN" "$LIVE_JSON" "${LIVE_RC:-}" <<'PY'
import json
import sys
from pathlib import Path

(
    ws, term, repo_dir, deploy_grep, skill_grep, workspace_grep, source_grep,
    addrs_uniq, direct_addrs_uniq, context_addrs_uniq, resolved_addr, network, rpc_url, check_call, check_args, expect,
    slot, balance_min, dry_run, live_json, live_rc
) = sys.argv[1:]

def lines(path: str, limit: int = 20):
    p = Path(path)
    if not p.exists():
        return []
    return [ln for ln in p.read_text(errors="replace").splitlines()[:limit] if ln.strip()]

payload = {
    "workspace": ws,
    "search_term": term,
    "repo_dir": repo_dir,
    "candidate_addresses": lines(addrs_uniq, 200),
    "direct_candidate_addresses": lines(direct_addrs_uniq, 200),
    "context_candidate_addresses": lines(context_addrs_uniq, 200),
    "resolved_address": resolved_addr or None,
    "network": network,
    "rpc_url_provided": bool(rpc_url),
    "live_request": {
        "call": check_call or None,
        "args": check_args or None,
        "expect": expect or None,
        "slot": slot or None,
        "balance_min": balance_min or None,
        "dry_run": dry_run == "1",
    },
    "matches": {
        "deploy_and_env": lines(deploy_grep),
        "skill_state": lines(skill_grep),
        "workspace_notes": lines(workspace_grep),
        "source": lines(source_grep),
    },
}

if live_rc != "":
    payload["live_check_exit_code"] = int(live_rc)
    p = Path(live_json)
    if p.exists() and p.read_text().strip():
        try:
            payload["live_check"] = json.loads(p.read_text())
        except json.JSONDecodeError:
            payload["live_check_raw"] = p.read_text()

print(json.dumps(payload, indent=2))
PY
  exit 0
fi

echo "=== deploy-state-lookup: $SEARCH_TERM ==="
echo "workspace: $WS"
echo "source-root : $SRC_ROOT"
echo ""

if [ -s "$DEPLOY_GREP" ]; then
  echo "## Deploy/config matches"
  head -20 "$DEPLOY_GREP" | sed 's/^/  /'
  echo ""
fi

if [ -s "$SKILL_GREP" ]; then
  echo "## .skill_state.yaml references"
  head -15 "$SKILL_GREP" | sed 's/^/  /'
  echo ""
fi

if [ -s "$WORKSPACE_GREP" ]; then
  echo "## Workspace notes / status / staging references"
  head -20 "$WORKSPACE_GREP" | sed 's/^/  /'
  echo ""
fi

echo "## Source references to \"$SEARCH_TERM\" (first 10)"
if [ -s "$SOURCE_GREP" ]; then
  head -10 "$SOURCE_GREP" | sed 's/^/  /'
else
  echo "  (no direct source references found)"
fi
echo ""

echo "## Candidate addresses"
if [ "$CANDIDATE_COUNT" -gt 0 ]; then
  sed 's/^/  /' "$ADDRS_UNIQ"
else
  echo "  (none extracted from deployment/config matches)"
fi
echo ""

if [ -n "$RESOLVED_ADDR" ]; then
  echo "## Resolved address"
  echo "  $RESOLVED_ADDR"
  echo ""
fi

if [ "$LIVE_REQUESTED" -eq 1 ]; then
  echo "## Live-state handoff"
  if [ -n "$RESOLVED_ADDR" ]; then
    echo "  forwarded to tools/live-state-checker.py"
    [ -n "$CHECK_CALL" ] && echo "  call    : $CHECK_CALL"
    [ -n "$CHECK_ARGS" ] && echo "  args    : $CHECK_ARGS"
    [ -n "$EXPECT" ] && echo "  expect  : $EXPECT"
    [ -n "$SLOT" ] && echo "  slot    : $SLOT"
    [ -n "$BALANCE_MIN" ] && echo "  min-b   : $BALANCE_MIN"
    [ "$DRY_RUN" -eq 1 ] && echo "  dry-run : yes"
    echo ""
  else
    echo "  [warn] live check requested, but no unique address was resolved."
    echo "         Re-run with --address 0x... to force the target."
    echo ""
  fi
fi

echo "=== end ==="
