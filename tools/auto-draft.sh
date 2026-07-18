#!/usr/bin/env bash
# auto-draft.sh — R57 C4 closer: auto-generate a Cantina-style submission draft
# from a detector hit (scan → draft ≤ 5 min operator-edit target).
#
# Usage:
#   ./tools/auto-draft.sh <workspace> <detector-name> <file:line> \
#       [--severity auto|low|med|high|crit]
#
# Behavior:
#   1. Loads reference/patterns.dsl/<detector-name>.yaml (wiki_* fields, severity, help)
#   2. Reads the source file ±20 lines around <line>
#   3. Reads <ws>/SCOPE.md, OOS_CHECKLIST.md, SEVERITY_CAPS.md
#   4. Checks whether the hit contract looks in-scope (warn but continue if unclear)
#   5. Renders a submission draft based on templates/cantina_submission.md
#      New (R57): inline Foundry PoC scaffold, rubric-example citation, derived
#      severity rationale — reduces operator-TODO markers from ~8-12 to ≤4.
#   6. Writes to <ws>/drafts/<slug>_auto.md
#   7. Chains into scope-review-inline.sh + time-engagement.sh draft_ready (best-effort)
#
# Exit codes:
#   0 — draft written
#   1 — usage error
#   2 — required workspace or detector yaml missing
#   3 — source file or line invalid
set -u

AUDITOOOR_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
PATTERNS_DIR="$AUDITOOOR_DIR/reference/patterns.dsl"
TEMPLATE="$AUDITOOOR_DIR/templates/cantina_submission.md"
RUBRIC_EXAMPLES="$AUDITOOOR_DIR/templates/rubric_examples.md"

usage() {
    cat >&2 <<'EOF'
usage: auto-draft.sh <workspace> <detector-name> <file:line> [--severity auto|low|med|high|crit]

  <workspace>      e.g. ~/audits/polymarket
  <detector-name>  basename of reference/patterns.dsl/<name>.yaml
                   (hyphens or underscores both accepted)
  <file:line>      absolute path to source file + hit line, colon-separated
  --severity       override the rubric-cap-applied severity (default: auto)
EOF
}

if [ "$#" -lt 3 ]; then
    usage; exit 1
fi

WS="$1"; DET_RAW="$2"; HIT_RAW="$3"; shift 3
SEV_OVERRIDE="auto"
while [ "$#" -gt 0 ]; do
    case "$1" in
        --severity)
            shift
            SEV_OVERRIDE="${1:-auto}"; shift || true ;;
        --severity=*)
            SEV_OVERRIDE="${1#--severity=}"; shift ;;
        *)
            echo "[auto-draft] unknown flag: $1" >&2; usage; exit 1 ;;
    esac
done

# -------- Workspace checks (step 3) --------
if [ ! -d "$WS" ]; then
    echo "[auto-draft] workspace not found: $WS" >&2; exit 2
fi
if [ ! -f "$WS/SCOPE.md" ]; then
    echo "[auto-draft] missing $WS/SCOPE.md — run tools/fetch-scope.sh" >&2; exit 2
fi

# -------- Detector yaml (step 1) --------
# Accept either underscore or hyphen form.
DET_UND="${DET_RAW//-/_}"
DET_HYP="${DET_RAW//_/-}"
DET_YAML=""
for cand in "$PATTERNS_DIR/${DET_RAW}.yaml" "$PATTERNS_DIR/${DET_UND}.yaml" "$PATTERNS_DIR/${DET_HYP}.yaml"; do
    if [ -f "$cand" ]; then DET_YAML="$cand"; break; fi
done
if [ -z "$DET_YAML" ]; then
    echo "[auto-draft] detector yaml not found for '$DET_RAW'" >&2
    echo "             searched: ${DET_RAW}.yaml ${DET_UND}.yaml ${DET_HYP}.yaml" >&2
    echo "             run: tools/detector-tier.sh list  (to enumerate available names)" >&2
    exit 2
fi

# -------- Source location (step 2) --------
SRC_FILE="${HIT_RAW%:*}"
SRC_LINE="${HIT_RAW##*:}"
case "$SRC_LINE" in ''|*[!0-9]*) echo "[auto-draft] invalid file:line '$HIT_RAW'" >&2; exit 3 ;; esac
if [ ! -f "$SRC_FILE" ]; then
    echo "[auto-draft] source file not found: $SRC_FILE" >&2; exit 3
fi
SRC_TOTAL=$(wc -l < "$SRC_FILE" | tr -d ' ')
if [ "$SRC_LINE" -lt 1 ] || [ "$SRC_LINE" -gt "$SRC_TOTAL" ]; then
    echo "[auto-draft] line $SRC_LINE out of range (file has $SRC_TOTAL lines)" >&2
    exit 3
fi

CTX_START=$(( SRC_LINE - 10 )); [ "$CTX_START" -lt 1 ] && CTX_START=1
CTX_END=$(( SRC_LINE + 10 )); [ "$CTX_END" -gt "$SRC_TOTAL" ] && CTX_END="$SRC_TOTAL"
SRC_SNIPPET=$(awk -v s="$CTX_START" -v e="$CTX_END" 'NR>=s && NR<=e {print}' "$SRC_FILE")
CONTRACT_BASENAME=$(basename "$SRC_FILE" .sol)
# Extract function name near the hit line by scanning backward for the nearest
# `function <name>(` declaration.
FN_NAME=$(awk -v hit="$SRC_LINE" '
    /function[[:space:]]+[A-Za-z_][A-Za-z0-9_]*[[:space:]]*\(/ && NR <= hit {
        match($0, /function[[:space:]]+[A-Za-z_][A-Za-z0-9_]*/)
        last = substr($0, RSTART+9, RLENGTH-9); gsub(/[[:space:]]/, "", last)
    }
    END { print last }
' "$SRC_FILE")
[ -z "$FN_NAME" ] && FN_NAME="<function>"

# -------- R57: Extract pragma from source file --------
# Capture the pragma version string; default to ^0.8.19 if ambiguous.
SRC_PRAGMA=$(grep -m1 -oE 'pragma solidity [^;]+' "$SRC_FILE" 2>/dev/null | sed 's/pragma solidity //' | tr -d ' ' || true)
[ -z "$SRC_PRAGMA" ] && SRC_PRAGMA="^0.8.19"
# If the version has no operator prefix, add ^.
case "$SRC_PRAGMA" in
    [0-9]*) SRC_PRAGMA="^${SRC_PRAGMA}" ;;
esac

# -------- R57: Detect target network from SCOPE.md heuristic --------
# Polymarket lives on Polygon; fall back to mainnet if no polygon signal found.
NETWORK="POLYGON"
NETWORK_RPC_VAR="POLYGON_RPC_URL"
NETWORK_RPC_FALLBACK="https://polygon.llamarpc.com"
if grep -iqE "mainnet|ethereum" "$WS/SCOPE.md" 2>/dev/null && \
   ! grep -iqE "polygon" "$WS/SCOPE.md" 2>/dev/null; then
    NETWORK="MAINNET"
    NETWORK_RPC_VAR="MAINNET_RPC_URL"
    NETWORK_RPC_FALLBACK="https://eth.llamarpc.com"
fi

# -------- Parse detector yaml (step 1 continued) --------
# Use python3 for robust YAML extraction; falls back to grep if PyYAML missing.
read_field() {
    local field="$1"
    python3 - "$DET_YAML" "$field" 2>/dev/null <<'PY' || true
import sys, yaml
path = sys.argv[1]; field = sys.argv[2]
try:
    with open(path) as f:
        doc = yaml.safe_load(f) or {}
    v = doc.get(field)
    if v is None:
        sys.exit(0)
    print(str(v))
except Exception:
    sys.exit(0)
PY
}
WIKI_TITLE=$(read_field wiki_title)
WIKI_DESC=$(read_field wiki_description)
WIKI_EXPLOIT=$(read_field wiki_exploit_scenario)
WIKI_RECO=$(read_field wiki_recommendation)
DET_SEV=$(read_field severity)
DET_HELP=$(read_field help)
[ -z "$WIKI_TITLE" ] && WIKI_TITLE="$(basename "$DET_YAML" .yaml)"
[ -z "$WIKI_DESC" ]  && WIKI_DESC="(detector yaml missing wiki_description)"
[ -z "$WIKI_EXPLOIT" ] && WIKI_EXPLOIT="(detector yaml missing wiki_exploit_scenario)"
[ -z "$WIKI_RECO" ]    && WIKI_RECO="(detector yaml missing wiki_recommendation)"
[ -z "$DET_SEV" ]      && DET_SEV="medium"
[ -z "$DET_HELP" ]     && DET_HELP=""

# -------- Scope check (step 3-4) --------
SCOPE_VERDICT="IN-SCOPE"
if ! grep -iqE "\\b${CONTRACT_BASENAME}\\b" "$WS/SCOPE.md"; then
    SCOPE_VERDICT="SCOPE-UNCLEAR"
    echo "[auto-draft] warning: '$CONTRACT_BASENAME' not found in $WS/SCOPE.md — marking draft SCOPE-UNCLEAR" >&2
fi

# -------- R51: Resolve concrete in-scope contract (step 3b) --------
# When the source file is a mixin (abstract contract), find the concrete contract
# that inherits from it AND is listed in SCOPE.md / scope.json. Report that
# concrete contract (with its deployed address) as the submission Target.
TARGET_CONTRACT="$CONTRACT_BASENAME"
TARGET_ADDRESS=""
TARGET_NOTE=""

# Build the list of in-scope contract names (from SCOPE.md table rows).
# Row format: `| <Name> | <Address> |` — extract name + address.
SCOPE_NAMES_FILE="$(mktemp -t auto_draft_scope_names.XXXXXX)"
SCOPE_ADDRS_FILE="$(mktemp -t auto_draft_scope_addrs.XXXXXX)"
trap 'rm -f "$SCOPE_NAMES_FILE" "$SCOPE_ADDRS_FILE"' EXIT

awk -F'|' '
    /^\|[[:space:]]*[A-Za-z]/ {
        name = $2; addr = $3
        gsub(/^[[:space:]]+|[[:space:]]+$/, "", name)
        gsub(/^[[:space:]]+|[[:space:]]+$/, "", addr)
        # Strip parenthetical annotations like " (v1)" or " (integration only)".
        sub(/[[:space:]]*\(.*\)[[:space:]]*$/, "", name)
        if (name == "Contract" || name == "Severity") next
        if (addr ~ /^0x[0-9a-fA-F]+$/) {
            print name >> names
            print addr >> addrs
        }
    }
' names="$SCOPE_NAMES_FILE" addrs="$SCOPE_ADDRS_FILE" "$WS/SCOPE.md" 2>/dev/null || true

lookup_address() {
    # $1 = contract name; prints address or "" if not found.
    local want="$1" i=1 line addr
    while IFS= read -r line; do
        if [ "$line" = "$want" ]; then
            addr=$(awk -v n="$i" 'NR==n {print}' "$SCOPE_ADDRS_FILE")
            printf '%s' "$addr"
            return 0
        fi
        i=$((i+1))
    done < "$SCOPE_NAMES_FILE"
    printf ''
}

# Detect whether the source lives under a v2 tree; when it does, prefer the
# `<name>V2` scope entry over the un-suffixed one (same source name, two
# deployments — v1 at un-suffixed, v2 at suffixed).
IS_V2_SRC=0
case "$SRC_FILE" in *"/src-v2/"*) IS_V2_SRC=1 ;; esac

# If the current contract name already appears verbatim in SCOPE.md with an
# address, capture it directly (preferring V2 when the source is under src-v2).
DIRECT_ADDR=""
DIRECT_V2_ADDR=""
if [ "$IS_V2_SRC" = "1" ]; then
    DIRECT_V2_ADDR=$(lookup_address "${CONTRACT_BASENAME}V2")
fi
if [ -n "$DIRECT_V2_ADDR" ]; then
    TARGET_CONTRACT="${CONTRACT_BASENAME}V2"
    TARGET_ADDRESS="$DIRECT_V2_ADDR"
    TARGET_NOTE="source \`$CONTRACT_BASENAME\` (src-v2) — deployed as \`${CONTRACT_BASENAME}V2\`"
elif DIRECT_ADDR=$(lookup_address "$CONTRACT_BASENAME") && [ -n "$DIRECT_ADDR" ]; then
    TARGET_ADDRESS="$DIRECT_ADDR"
else
    :
    # Search src-v2/ (or src/) for any `contract X is ... <mixin-name>` where
    # mixin-name == $CONTRACT_BASENAME. Collect candidate concrete contracts.
    SRC_ROOTS=()
    [ -d "$WS/src-v2" ] && SRC_ROOTS+=("$WS/src-v2")
    [ -d "$WS/src" ]    && SRC_ROOTS+=("$WS/src")

    CAND_FILE="$(mktemp -t auto_draft_candidates.XXXXXX)"
    trap 'rm -f "$SCOPE_NAMES_FILE" "$SCOPE_ADDRS_FILE" "$CAND_FILE"' EXIT

    if [ "${#SRC_ROOTS[@]}" -gt 0 ]; then
        # grep for `contract X is ... CONTRACT_BASENAME ...` (non-abstract only).
        grep -rhE "^[[:space:]]*contract[[:space:]]+[A-Za-z_][A-Za-z0-9_]*[[:space:]]+is[[:space:]]+[^{]*\\b${CONTRACT_BASENAME}\\b" \
             "${SRC_ROOTS[@]}" 2>/dev/null \
            | sed -E 's/^[[:space:]]*contract[[:space:]]+([A-Za-z_][A-Za-z0-9_]*)[[:space:]]+is.*/\1/' \
            | sort -u > "$CAND_FILE" || true
    fi

    # Among candidates, prefer one that appears in SCOPE.md table.
    # When the source is under `src-v2/`, the V2-suffixed scope entry (e.g.
    # `CTFExchangeV2`) is the deployed target even though the concrete source
    # contract is still named `CTFExchange`. Check V2 naming FIRST when the
    # source path indicates a v2 tree.
    IS_V2_SRC=0
    case "$SRC_FILE" in *"/src-v2/"*) IS_V2_SRC=1 ;; esac

    if [ -s "$CAND_FILE" ]; then
        if [ "$IS_V2_SRC" = "1" ]; then
            while IFS= read -r cand; do
                [ -z "$cand" ] && continue
                v2_addr=$(lookup_address "${cand}V2")
                if [ -n "$v2_addr" ]; then
                    TARGET_CONTRACT="${cand}V2"
                    TARGET_ADDRESS="$v2_addr"
                    TARGET_NOTE="source is mixin \`$CONTRACT_BASENAME\` inherited by \`$cand\` (src-v2) — deployed as \`${cand}V2\`"
                    SCOPE_VERDICT="IN-SCOPE"
                    break
                fi
            done < "$CAND_FILE"
        fi

        if [ -z "$TARGET_ADDRESS" ]; then
            while IFS= read -r cand; do
                [ -z "$cand" ] && continue
                cand_addr=$(lookup_address "$cand")
                if [ -n "$cand_addr" ]; then
                    TARGET_CONTRACT="$cand"
                    TARGET_ADDRESS="$cand_addr"
                    TARGET_NOTE="source is mixin \`$CONTRACT_BASENAME\` inherited by concrete in-scope \`$cand\`"
                    SCOPE_VERDICT="IN-SCOPE"
                    break
                fi
            done < "$CAND_FILE"
        fi
    fi
fi

# -------- OOS overlap (step 4) --------
# R51: bump min-token-length to 6 and exclude common English words that cause
# false-positive OOS overlap (observed in R50 dogfood: "risk", "user", "state",
# "value", "check", "token", "asset", "event"). This reduces operator triage
# noise without losing signal on the real OOS bullets.
OOS_STOPWORDS=" risk risks user users state states value values check checks token tokens asset assets event events issue issues audit audits input inputs output outputs should would could access system design report reports bounty impact impacts attack attacks without within before after because during against between through where which while whose there their these those about above below under other otherwise caller callers address addresses contract contracts function functions return returns require requires "
OOS_OVERLAP=""
if [ -f "$WS/OOS_CHECKLIST.md" ]; then
    # Look for weak overlap: any detector keyword appearing in OOS bullets.
    for kw in $(echo "$DET_HELP $WIKI_TITLE" | tr 'A-Z' 'a-z' | tr -cs 'a-z0-9' ' '); do
        [ "${#kw}" -lt 6 ] && continue
        case "$OOS_STOPWORDS" in *" $kw "*) continue ;; esac
        if grep -iq "\\b$kw\\b" "$WS/OOS_CHECKLIST.md" 2>/dev/null; then
            OOS_OVERLAP="$OOS_OVERLAP $kw"
        fi
    done
    OOS_OVERLAP=$(echo "$OOS_OVERLAP" | xargs)
fi

# -------- Severity caps (step 5) --------
CAP_NOTE=""
if [ -f "$WS/SEVERITY_CAPS.md" ]; then
    if grep -viq "no severity caps parsed" "$WS/SEVERITY_CAPS.md" && grep -q "-" "$WS/SEVERITY_CAPS.md"; then
        CAP_NOTE=$(grep -iE "^[-*] " "$WS/SEVERITY_CAPS.md" | head -3)
    fi
fi

# -------- Severity resolution --------
if [ "$SEV_OVERRIDE" != "auto" ]; then
    FINAL_SEV="$SEV_OVERRIDE"
else
    FINAL_SEV=$(echo "$DET_SEV" | tr 'A-Z' 'a-z')
    case "$FINAL_SEV" in
        critical) FINAL_SEV="crit" ;;
        high) FINAL_SEV="high" ;;
        medium) FINAL_SEV="med" ;;
        low) FINAL_SEV="low" ;;
        *) FINAL_SEV="med" ;;
    esac
fi

# -------- R57: Rubric citation lookup --------
# Match FINAL_SEV to the first blockquote in the corresponding tier section of
# templates/rubric_examples.md. Gracefully degrades if file is missing.
RUBRIC_CITATION=""
if [ -f "$RUBRIC_EXAMPLES" ]; then
    RUBRIC_CITATION=$(python3 - "$RUBRIC_EXAMPLES" "$FINAL_SEV" 2>/dev/null <<'PY' || true
import sys, re
path = sys.argv[1]
sev  = sys.argv[2].lower()   # crit / high / med / low

tier_map = {"crit": "Critical", "high": "High", "med": "Medium", "low": "Low"}
tier_label = tier_map.get(sev, "Low")

with open(path) as f:
    text = f.read()

# Find the section header for the tier, then grab the first blockquote block.
section_pat = rf'## {tier_label} impact examples.*?(?=\n## |\Z)'
sec_m = re.search(section_pat, text, re.DOTALL | re.IGNORECASE)
if not sec_m:
    sys.exit(0)

section = sec_m.group(0)
# A rubric blockquote starts with "> **" and ends at the blank line after the last "> " line.
bq_pat = r'(> \*\*[^\n]+\n(?:> [^\n]*\n)+)'
bq_m = re.search(bq_pat, section)
if bq_m:
    print(bq_m.group(1).rstrip())
PY
    )
fi
if [ -z "$RUBRIC_CITATION" ]; then
    # Graceful degradation: specific placeholder, not a bare "operator:" marker
    case "$FINAL_SEV" in
        crit) RUBRIC_CITATION="> (rubric_examples.md not matched — operator: cite a Critical example from the bounty rubric)" ;;
        high) RUBRIC_CITATION="> (rubric_examples.md not matched — operator: cite a High example from the bounty rubric)" ;;
        med)  RUBRIC_CITATION="> (rubric_examples.md not matched — operator: cite a Medium example from the bounty rubric)" ;;
        *)    RUBRIC_CITATION="> (rubric_examples.md not matched — operator: cite a Low example from the bounty rubric)" ;;
    esac
fi

# -------- R57: Severity rationale derivation --------
# Single sentence combining detector IMPACT, scope verdict, OOS overlap, and caps.
_sev_upper=$(echo "$FINAL_SEV" | tr 'a-z' 'A-Z')
_oos_note="none"
[ -n "$OOS_OVERLAP" ] && _oos_note="$OOS_OVERLAP (review OOS_CHECKLIST)"
_cap_inline="none"
[ -n "$CAP_NOTE" ] && _cap_inline="see SEVERITY_CAPS.md"

SEV_RATIONALE="Severity per rubric: **${_sev_upper}** because the detector IMPACT class (${DET_SEV}) matches the ${FINAL_SEV} category in the Cantina rubric (see citation below). Hit is ${SCOPE_VERDICT}. Known OOS keyword overlap: ${_oos_note}. Applied severity caps: ${_cap_inline}."

# -------- Build title (<=120 chars) --------
# Keep first 100 chars of wiki_title, then append specific contract.function
TITLE_BASE=$(printf '%s' "$WIKI_TITLE" | tr -d '\n\r')
TITLE="${CONTRACT_BASENAME}.${FN_NAME}(): ${TITLE_BASE}"
TITLE=$(printf '%s' "$TITLE" | cut -c1-120)

# -------- Output path --------
SLUG_BASE=$(basename "$DET_YAML" .yaml)
DRAFT_DIR="$WS/drafts"
mkdir -p "$DRAFT_DIR"
SLUG="${SLUG_BASE}_${CONTRACT_BASENAME}_${FN_NAME}"
# Sanitize slug (alnum + _)
SLUG=$(printf '%s' "$SLUG" | tr -c 'A-Za-z0-9_' '_' | sed 's/__*/_/g')
OUT="$DRAFT_DIR/${SLUG}_auto.md"

# Relative source path (for display)
if [[ "$SRC_FILE" == $WS/* ]]; then
    REL_SRC="${SRC_FILE#$WS/}"
else
    REL_SRC="$SRC_FILE"
fi

# -------- R57: PoC scaffold variables --------
# Ensure the pragma is forge-std safe (>=0.6.0); fall back to ^0.8.19.
POC_PRAGMA="$SRC_PRAGMA"
case "$POC_PRAGMA" in
    "^0."[0-5]*|"=0."[0-5]*|">=0."[0-5]*) POC_PRAGMA="^0.8.19" ;;
esac
# Interface and contract name for the PoC file.
IFACE_NAME="I${TARGET_CONTRACT}"
IFACE_NAME=$(printf '%s' "$IFACE_NAME" | tr -c 'A-Za-z0-9_' '_')
# Truncate slug so file names stay sane.
POC_SLUG=$(printf '%s' "$SLUG" | cut -c1-50)

# -------- Emit draft (step 6-7) --------
{
    printf '# %s\n\n' "$TITLE"
    printf '> **Auto-generated by** `tools/auto-draft.sh` — operator must review before submission.\n'
    printf '> **Detector:** `%s` (severity: %s)\n' "$SLUG_BASE" "$DET_SEV"
    printf '> **Scope verdict:** %s\n' "$SCOPE_VERDICT"
    if [ -n "$OOS_OVERLAP" ]; then
        printf '> **OOS keyword overlap (review):** %s\n' "$OOS_OVERLAP"
    else
        printf '> **OOS keyword overlap:** none detected\n'
    fi
    if [ -n "$CAP_NOTE" ]; then
        printf '> **Severity caps present:**\n'
        printf '%s\n' "$CAP_NOTE" | sed 's/^/> /'
    fi
    printf '\n---\n\n'

    # R51: Target asset — prefer concrete in-scope contract + deployed address.
    if [ -n "$TARGET_ADDRESS" ]; then
        printf '## Target asset\n'
        printf '**Target asset:** `%s` (in-scope, deployed at %s)\n\n' "$TARGET_CONTRACT" "$TARGET_ADDRESS"
        if [ -n "$TARGET_NOTE" ]; then
            printf '> %s.\n' "$TARGET_NOTE"
        fi
        printf 'Source: `%s`\n\n' "$REL_SRC"
    else
        printf '## Target asset\n'
        printf '**Target asset:** `%s` (scope-unclear — operator: confirm deployed concrete contract)\n\n' "$CONTRACT_BASENAME"
        printf 'Source: `%s`\n\n' "$REL_SRC"
    fi

    # R57: Severity section now includes derived rationale + rubric citation.
    printf '## Severity\n\n'
    printf -- '- **Detector-assigned:** %s\n' "$DET_SEV"
    printf -- '- **Applied (after rubric caps):** %s\n' "$FINAL_SEV"
    if [ -n "$CAP_NOTE" ]; then
        printf -- '- **Cap note:** see SEVERITY_CAPS.md\n'
    fi
    printf '\n%s\n\n' "$SEV_RATIONALE"
    printf '**Closest rubric example:**\n\n%s\n\n' "$RUBRIC_CITATION"

    printf '## Finding Title (%s chars)\n```\n%s\n```\n\n' "${#TITLE}" "$TITLE"

    printf '## Summary\n\n%s\n\n' "$WIKI_DESC"
    printf 'Specific match: `%s:%s` inside `%s.%s`.\n\n' "$REL_SRC" "$SRC_LINE" "$CONTRACT_BASENAME" "$FN_NAME"
    if [ "$SCOPE_VERDICT" = "SCOPE-UNCLEAR" ]; then
        printf '> **Operator TODO:** confirm target is in-scope (not obviously listed in SCOPE.md).\n\n'
    fi
    if [ -n "$OOS_OVERLAP" ]; then
        printf '> **Operator TODO:** review OOS bullets — overlap keywords: %s\n\n' "$OOS_OVERLAP"
    fi

    printf '## Finding Description\n\n### Security guarantee broken\n%s\n\n' "$DET_HELP"
    printf '### Call chain / root cause\n\n'
    printf '```solidity\n// %s:%s-%s  (hit line %s)\n%s\n```\n\n' "$REL_SRC" "$CTX_START" "$CTX_END" "$SRC_LINE" "$SRC_SNIPPET"

    printf '## Attacker model\n\n%s\n\n' "$WIKI_EXPLOIT"
    printf 'Adapted to target: %s.%s at %s:%s.\n\n' "$CONTRACT_BASENAME" "$FN_NAME" "$REL_SRC" "$SRC_LINE"

    printf '## Exploit steps (skeleton — operator fills concrete invocations)\n\n'
    printf '1. Precondition: <describe on-chain state — e.g. role grant missing, price state, balance>.\n'
    printf '2. Attacker calls `%s.%s(...)` with <args>.\n' "$CONTRACT_BASENAME" "$FN_NAME"
    printf '3. Observe <outcome: revert / wrong state / drained funds / stuck>.\n'
    printf '4. On-chain evidence: `cast call` / `cast send` commands.\n\n'

    # R57: Impact Explanation now includes derived rationale + rubric citation inline.
    printf '## Impact Explanation\n\n'
    printf -- '- Detector severity: **%s**\n' "$DET_SEV"
    printf -- '- Applied severity: **%s**\n' "$FINAL_SEV"
    printf '\n%s\n\n' "$SEV_RATIONALE"
    printf '**Rubric example match:**\n\n%s\n\n' "$RUBRIC_CITATION"

    # R57: Likelihood now has a structured 3-item skeleton instead of bare placeholder.
    printf '## Likelihood Explanation\n\n'
    printf 'Likelihood preconditions (operator: tighten with concrete on-chain state):\n\n'
    printf '1. <precondition A — e.g. role not set / value in specific range / external event>\n'
    printf '2. <precondition B — attacker cost / capital requirement>\n'
    printf '3. <precondition C — timing / ordering constraint if any>\n\n'

    printf '## Recommendation\n\n%s\n\n' "$WIKI_RECO"

    # R57: Inline Foundry PoC scaffold replaces the old bare (plan) section.
    printf '## Proof of Concept\n\n'
    printf '```solidity\n'
    printf '// SPDX-License-Identifier: MIT\n'
    printf 'pragma solidity %s;\n\n' "$POC_PRAGMA"
    printf 'import { Test } from "forge-std/Test.sol";\n\n'
    printf '// Minimal inline interface — add only what the PoC calls.\n'
    printf '// Full ABI at: %s\n' "$REL_SRC"
    printf 'interface %s {\n' "$IFACE_NAME"
    printf '    function %s(/* operator: paste sig */) external;\n' "$FN_NAME"
    printf '}\n\n'
    printf 'contract PoC_%s is Test {\n' "$POC_SLUG"
    if [ -n "$TARGET_ADDRESS" ]; then
        printf '    %s constant TARGET = %s(%s);\n' "$IFACE_NAME" "$IFACE_NAME" "$TARGET_ADDRESS"
    else
        printf '    // TODO: insert deployed address of %s\n' "$TARGET_CONTRACT"
        printf '    %s constant TARGET = %s(address(0));\n' "$IFACE_NAME" "$IFACE_NAME"
    fi
    printf '\n'
    printf '    address attacker = makeAddr("attacker");\n\n'
    printf '    function setUp() public {\n'
    printf '        // Fork %s at the current head.\n' "$NETWORK"
    printf '        // Canonical RPC fallback: %s\n' "$NETWORK_RPC_FALLBACK"
    printf '        vm.createSelectFork(vm.envString("%s"));\n' "$NETWORK_RPC_VAR"
    printf '    }\n\n'
    printf '    function test_%s_exploit() public {\n' "$POC_SLUG"
    printf '        // 1. Precondition: <describe required on-chain state>\n'
    printf '        //    e.g. verify a role is missing, a balance is zero, a flag is set\n\n'
    printf '        // 2. Attacker action:\n'
    printf '        vm.prank(attacker);\n'
    printf '        TARGET.%s(/* operator: fill args */);\n' "$FN_NAME"
    printf '\n'
    printf '        // 3. Assert exploit outcome:\n'
    printf '        //    e.g. assertTrue(victimLost, "funds were drained");\n'
    printf '        //         assertEq(STATE_AFTER, UNEXPECTED_VALUE);\n'
    printf '    }\n'
    printf '}\n'
    printf '```\n\n'
    printf 'Run:\n'
    printf '```bash\n%s=%s \\\n' "$NETWORK_RPC_VAR" "$NETWORK_RPC_FALLBACK"
    printf '  forge test --match-contract PoC_%s -vvvv\n' "$POC_SLUG"
    printf '```\n\n'
    printf '> **Operator TODO (PoC only):** fill the function signature in `%s`, add\n' "$IFACE_NAME"
    printf '> concrete exploit logic in steps 1-3, run `forge test` to confirm.\n\n'

    printf -- '---\n\n## Auto-draft metadata\n\n'
    printf -- '- **Source detector yaml:** `%s`\n' "${DET_YAML#$AUDITOOOR_DIR/}"
    printf -- '- **Generated:** %s\n' "$(date -u +%Y-%m-%dT%H:%M:%SZ)"
    printf -- '- **Generator:** `tools/auto-draft.sh`\n'
} > "$OUT"

echo "[auto-draft] wrote: $OUT"

# -------- Chain: scope-review-inline.sh (best-effort) --------
SCOPE_INLINE="$AUDITOOOR_DIR/tools/scope-review-inline.sh"
if [ -x "$SCOPE_INLINE" ]; then
    echo "[auto-draft] chaining: scope-review-inline.sh"
    "$SCOPE_INLINE" "$WS" "$OUT" || echo "[auto-draft] scope-review-inline.sh exited non-zero (non-fatal)"
else
    echo "[auto-draft] skipping scope-review-inline.sh (not executable)"
fi

# -------- Chain: time-engagement.sh draft_ready (best-effort) --------
TIME_ENG="$AUDITOOOR_DIR/tools/time-engagement.sh"
if [ -x "$TIME_ENG" ]; then
    echo "[auto-draft] chaining: time-engagement.sh draft_ready"
    "$TIME_ENG" "$WS" draft_ready || echo "[auto-draft] time-engagement.sh exited non-zero (non-fatal)"
else
    echo "[auto-draft] skipping time-engagement.sh (not executable)"
fi

echo "[auto-draft] done."
exit 0
