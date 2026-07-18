#!/usr/bin/env bash
# scope-review-inline.sh — R44 U2/U8 wiring: rule-based inline scope-review.
#
# The Task-agent variant (scope-review.sh) emits a brief and waits for a
# sub-agent to paste back the VERDICT block. Until the MCP/Task dispatch
# channel is wired, this tool applies a deterministic heuristic directly
# over the brief + draft + graph-query + OOS checklist, and emits a
# `*.heuristic-review.md` compatible with pre-submit-check Check #11.
#
# Pipeline:
#   1. Ensure <ws>/scope_review/<basename>.brief.md exists (or generate it).
#   2. Call graph-query.sh --similar-to --json to score prior-audit matches.
#   3. Count OOS-N bullets present in OOS_CHECKLIST; fingerprint-grep the
#      draft against each bullet to find strong overlap.
#   4. Combine signals into a VERDICT using thresholds shared with
#      novel-vector-check.sh (score >=15 DUPE, 5-14 SAME-CLASS, <5 NOVEL;
#      OOS-keyword overlap + scope-ack language -> OOS-ACKNOWLEDGED).
#   5. Emit <ws>/scope_review/<basename>.heuristic-review.md containing
#      the VERDICT block, citations, and 3-sentence auto reasoning.
#
# This is NOT an LLM call; it's a reproducible heuristic with high
# consistency against the same thresholds used elsewhere.
#
# Usage:
#   ./tools/scope-review-inline.sh <workspace> <draft.md>
#
# Exit codes:
#   0 — heuristic-review.md written (safe to proceed to pre-submit-check)
#   1 — missing workspace context
#   2 — usage error

set -u

WS="${1:-}"
DRAFT="${2:-}"

if [ -z "$WS" ] || [ ! -d "$WS" ] || [ -z "$DRAFT" ] || [ ! -f "$DRAFT" ]; then
  echo "usage: $0 <workspace> <draft.md>" >&2
  exit 2
fi

AUDITOOOR_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
SCOPE_REVIEW_SH="$AUDITOOOR_DIR/tools/scope-review.sh"
GRAPH_QUERY_SH="$AUDITOOOR_DIR/tools/graph-query.sh"

OUT_DIR="$WS/scope_review"
mkdir -p "$OUT_DIR"
BASENAME=$(basename "$DRAFT" .md)
BRIEF="$OUT_DIR/${BASENAME}.brief.md"
OUT="$OUT_DIR/${BASENAME}.heuristic-review.md"

# ---------- HARD gate ----------
[ -f "$WS/OOS_CHECKLIST.md" ] || { echo "[scope-review-inline] missing $WS/OOS_CHECKLIST.md" >&2; exit 1; }
[ -f "$WS/SCOPE.md" ]         || { echo "[scope-review-inline] missing $WS/SCOPE.md" >&2; exit 1; }

# ---------- (1) Generate brief if missing ----------
if [ ! -f "$BRIEF" ]; then
  if [ -x "$SCOPE_REVIEW_SH" ]; then
    "$SCOPE_REVIEW_SH" "$WS" "$DRAFT" >/dev/null 2>&1 || true
  fi
fi
BRIEF_EXISTS=0
[ -f "$BRIEF" ] && BRIEF_EXISTS=1

# ---------- (2) Graph-query similarity ----------
# We prefer hits from the SAME workspace — cross-workspace matches at low scores
# are near-guaranteed false positives (e.g., morpho Bundler reentrancy "looking
# like" a polymarket role-grant DoS because they share generic English tokens).
# Derive the current workspace name from its path basename.
WS_NAME=$(basename "$WS")
GRAPH_TOP_SCORE=0
GRAPH_TOP_AUDIT=""
GRAPH_TOP_FINDING=""
GRAPH_TOP_WORKSPACE=""
GRAPH_SAMEWS_SCORE=0
GRAPH_SAMEWS_AUDIT=""
GRAPH_SAMEWS_FINDING=""
GRAPH_ALL_HITS=""
if [ -x "$GRAPH_QUERY_SH" ]; then
  GRAPH_RAW_JSON=$("$GRAPH_QUERY_SH" --similar-to "$DRAFT" --limit 5 --json 2>/dev/null || true)
  GRAPH_RAW=$("$GRAPH_QUERY_SH" --similar-to "$DRAFT" --limit 5 2>/dev/null || true)
  GRAPH_ALL_HITS=$(echo "$GRAPH_RAW" | awk '/^\[score=/{print; getline nxt; print nxt}')
  if [ -n "$GRAPH_RAW_JSON" ]; then
    # Write JSON to a temp file so python can read from stdin cleanly
    # (chained heredocs are unreliable across shells).
    _TMP_JSON=$(mktemp /tmp/scope_review_graph.XXXXXX.json)
    printf '%s' "$GRAPH_RAW_JSON" > "$_TMP_JSON"
    _PY_ENV=$(WS_NAME="$WS_NAME" INPUT="$_TMP_JSON" python3 <<'PY' 2>/dev/null
import json, os, shlex
ws_name = os.environ.get("WS_NAME","")
with open(os.environ["INPUT"]) as f:
    data = json.load(f)
nodes = data.get("nodes", [])
def fmt(n):
    ws = n.get("workspace","")
    sa = n.get("source_audit","")
    fid = n.get("finding_id","")
    sev = n.get("severity","Unknown")
    title = (n.get("title","") or "").replace("\n"," ")[:180]
    score = n.get("similarity_score",0)
    audit = f"{ws}/{sa} {fid} ({sev})"
    return score, audit, title, ws
def shout(name, val):
    print(f"{name}={shlex.quote(str(val))}")
top = nodes[0] if nodes else None
if top:
    s,a,t,w = fmt(top)
    shout("GRAPH_TOP_SCORE", s)
    shout("GRAPH_TOP_AUDIT", a)
    shout("GRAPH_TOP_FINDING", t)
    shout("GRAPH_TOP_WORKSPACE", w)
samews = next((n for n in nodes if n.get("workspace","") == ws_name), None)
if samews:
    s,a,t,w = fmt(samews)
    shout("GRAPH_SAMEWS_SCORE", s)
    shout("GRAPH_SAMEWS_AUDIT", a)
    shout("GRAPH_SAMEWS_FINDING", t)
PY
)
    rm -f "$_TMP_JSON"
    # shellcheck disable=SC2086
    eval "$_PY_ENV"
  fi
fi
[ -z "$GRAPH_TOP_SCORE" ] && GRAPH_TOP_SCORE=0
[ -z "$GRAPH_SAMEWS_SCORE" ] && GRAPH_SAMEWS_SCORE=0

# ---------- (3) OOS bullet keyword overlap ----------
# Extract OOS-N bullet bodies; score each against the draft.
DRAFT_LOWER=$(tr 'A-Z' 'a-z' < "$DRAFT")
OOS_MATCHED_IDS=""
OOS_MATCHED_BULLETS=""
while IFS= read -r bullet; do
  # bullet line like: "- [ ] **OOS-1:** Unfixed vulnerabilities from previous audits..."
  [ -z "$bullet" ] && continue
  OOS_ID=$(echo "$bullet" | grep -oE 'OOS-[0-9]+' | head -1)
  [ -z "$OOS_ID" ] && continue
  # Strip markdown and OOS-N prefix
  BODY=$(echo "$bullet" | sed -E 's/^[[:space:]-]*\[[[:space:]x]\][[:space:]]*\*\*OOS-[0-9]+:\*\*[[:space:]]*//; s/\*\*//g' \
          | tr 'A-Z' 'a-z')
  # Tokenize bullet body: words >=5 chars, skip stopwords.
  TOKENS=$(echo "$BODY" | tr -s '[:space:][:punct:]' '\n' \
           | awk 'length($0) >= 5' \
           | grep -viE '^(which|their|there|these|those|about|after|before|between|should|would|could|include|including|without|within|https|github|platform|known|risks|other|design|issues|already|listed|mentioned)$' \
           | sort -u)
  # Count how many bullet tokens appear in draft_lower
  HITS=0
  for t in $TOKENS; do
    if echo "$DRAFT_LOWER" | grep -qE "\b${t}\b"; then
      HITS=$((HITS + 1))
    fi
  done
  TOTAL=$(echo "$TOKENS" | grep -c . || true)
  [ "$TOTAL" -gt 0 ] || TOTAL=1
  # Strong match threshold: >=3 tokens OR >=40% of bullet tokens.
  if [ "$HITS" -ge 3 ]; then
    OOS_MATCHED_IDS="$OOS_MATCHED_IDS $OOS_ID"
    OOS_MATCHED_BULLETS="${OOS_MATCHED_BULLETS}
  - ${OOS_ID} (tokens matched: ${HITS}/${TOTAL})"
  fi
done < <(grep -E '\*\*OOS-[0-9]+:\*\*' "$WS/OOS_CHECKLIST.md" || true)
OOS_MATCHED_IDS=$(echo "$OOS_MATCHED_IDS" | tr -s ' ' '\n' | grep -v '^$' | sort -u | tr '\n' ',' | sed 's/,$//; s/,/, /g')

# ---------- (4) Scope-acknowledgment language ----------
# Draft explicitly cites a prior audit as having acknowledged the issue.
SCOPE_ACK=0
SCOPE_ACK_QUOTE=""
if grep -iqE '(moved to _oos_rejected|fixed in pr|acknowledged as by-design|already raised|already recorded|dupe.?of.?audit|prior.audit.acknowledged|cantina.*§|quantstamp.*§|consensys.*§|spearbit.*§|openzeppelin.*§)' "$DRAFT"; then
  SCOPE_ACK=1
  SCOPE_ACK_QUOTE=$(grep -iE '(moved to _oos_rejected|fixed in pr|acknowledged as by-design|already raised|already recorded|dupe.?of.?audit|prior.audit.acknowledged)' "$DRAFT" | head -1 | sed 's/^[[:space:]]*//')
fi

# ---------- (5) Combine signals ----------
VERDICT="NOVEL"
CONFIDENCE="medium"
REASONING=""

# Decision thresholds:
#   - Same-workspace graph hit: standard thresholds 15/5 (matches novel-vector-check).
#   - Cross-workspace only: demand >= 20 before treating as SAME-CLASS; below that
#     treat as coincidental keyword overlap (different protocol is strong evidence
#     against duplication).
#   - OOS keyword overlap alone (no scope-ack language) is a WARNING, not a verdict
#     override — false positives are common on short bullet bodies.

SAMEWS_SCORE="$GRAPH_SAMEWS_SCORE"
SAMEWS_AUDIT="$GRAPH_SAMEWS_AUDIT"
SAMEWS_FINDING="$GRAPH_SAMEWS_FINDING"

# Rule A: draft itself says it's OOS (scope-ack language) AND OOS bullets overlap
if [ "$SCOPE_ACK" = "1" ] && [ -n "$OOS_MATCHED_IDS" ]; then
  VERDICT="OOS-ACKNOWLEDGED"
  CONFIDENCE="high"
  REASONING="Draft body explicitly cites prior-audit acknowledgment (\"${SCOPE_ACK_QUOTE}\"). OOS bullets matched: ${OOS_MATCHED_IDS}. Per Check #11, this draft should remain in _oos_rejected/."
# Rule B: same-workspace graph score >= 15 → DUPE
elif [ "$SAMEWS_SCORE" -ge 15 ]; then
  VERDICT="DUPE-OF-AUDIT"
  CONFIDENCE="high"
  REASONING="Citation-graph similarity score ${SAMEWS_SCORE} against prior finding in same workspace: ${SAMEWS_AUDIT} — ${SAMEWS_FINDING}. Score >=15 indicates contract + function + mechanism keywords align tightly with an existing audited finding; default action is to reject as duplicate."
# Rule C: same-workspace graph 5-14 → SAME-CLASS-DIFFERENT-VECTOR
elif [ "$SAMEWS_SCORE" -ge 5 ]; then
  VERDICT="SAME-CLASS-DIFFERENT-VECTOR"
  CONFIDENCE="medium"
  REASONING="Citation-graph similarity score ${SAMEWS_SCORE} against prior finding in same workspace: ${SAMEWS_AUDIT} — ${SAMEWS_FINDING}. Class-level overlap detected but vector may differ; submit only with explicit \"DIFFERENT VECTOR than <prior>\" framing. Run reframe-same-class.sh to generate the reframed draft."
# Rule D: cross-workspace very-high score (>=20) → SAME-CLASS (possible pattern reuse)
elif [ "$GRAPH_TOP_SCORE" -ge 20 ]; then
  VERDICT="SAME-CLASS-DIFFERENT-VECTOR"
  CONFIDENCE="low"
  REASONING="Citation-graph similarity score ${GRAPH_TOP_SCORE} against cross-protocol finding: ${GRAPH_TOP_AUDIT} — ${GRAPH_TOP_FINDING}. Cross-workspace match at this strength suggests a reusable pattern; verify attack-path-vs-path before filing."
# Rule E: default NOVEL (cross-workspace low scores are not evidence of dupe)
else
  VERDICT="NOVEL"
  if [ -n "$OOS_MATCHED_IDS" ]; then
    CONFIDENCE="medium"
    REASONING="No same-workspace prior-audit match (top same-ws score ${SAMEWS_SCORE}); top overall graph hit is cross-protocol at score ${GRAPH_TOP_SCORE} (${GRAPH_TOP_AUDIT}) which is expected noise. OOS bullets matched keyword-wise (${OOS_MATCHED_IDS}) but no scope-ack language in draft — likely false positive on generic tokens. Proceeding as NOVEL; operator should still spot-check the matched OOS bullets."
  elif [ "$GRAPH_TOP_SCORE" -gt 0 ]; then
    CONFIDENCE="high"
    REASONING="No same-workspace prior-audit match (top same-ws score ${SAMEWS_SCORE}); top overall graph hit is cross-protocol (${GRAPH_TOP_AUDIT}, score ${GRAPH_TOP_SCORE}) which is below the cross-workspace threshold. No OOS bullets matched. Draft appears novel; proceed to pre-submit-check.sh."
  else
    CONFIDENCE="high"
    REASONING="No prior-audit hits in citation graph. No OOS bullets matched keyword-wise. Draft appears novel; proceed to pre-submit-check.sh."
  fi
fi

# ---------- (6) Emit heuristic-review.md ----------
TS="$(date -u +%Y-%m-%dT%H:%M:%SZ)"
{
  echo "VERDICT: ${VERDICT}"
  echo "CONFIDENCE: ${CONFIDENCE}"
  # Citation: prefer same-workspace top match, fall back to overall top
  if [ "$SAMEWS_SCORE" -gt 0 ] && [ -n "$SAMEWS_AUDIT" ]; then
    echo "PRIOR-AUDIT CITATIONS: ${SAMEWS_AUDIT} (score=${SAMEWS_SCORE}, same-workspace)"
  elif [ "$GRAPH_TOP_SCORE" -gt 0 ] && [ -n "$GRAPH_TOP_AUDIT" ]; then
    echo "PRIOR-AUDIT CITATIONS: ${GRAPH_TOP_AUDIT} (score=${GRAPH_TOP_SCORE}, cross-workspace)"
  else
    echo "PRIOR-AUDIT CITATIONS: none"
  fi
  if [ -n "$OOS_MATCHED_IDS" ]; then
    echo "OOS CITATIONS: ${OOS_MATCHED_IDS}"
  else
    echo "OOS CITATIONS: none"
  fi
  echo "SEVERITY CAP: none"
  echo "SUBMISSION GUIDANCE:"
  case "$VERDICT" in
    NOVEL)
      echo "  - Proceed to ./tools/pre-submit-check.sh ${DRAFT}"
      ;;
    SAME-CLASS-DIFFERENT-VECTOR)
      _CITE="${SAMEWS_AUDIT:-$GRAPH_TOP_AUDIT}"
      echo "  - Verify attack path differs from cited prior finding; run ./tools/reframe-same-class.sh ${WS} ${DRAFT} \"${_CITE}\""
      echo "  - After reframe, re-run this tool on the reframed draft."
      ;;
    DUPE-OF-AUDIT)
      echo "  - Move draft to ${WS}/submissions/_oos_rejected/ unless operator can prove attack path is genuinely distinct."
      ;;
    OOS-ACKNOWLEDGED)
      echo "  - Draft is already flagged OOS; keep in _oos_rejected/. Do not submit."
      ;;
  esac
  echo "REASONING:"
  # Word-wrap reasoning at ~80 chars for readability (fold if available)
  if command -v fold >/dev/null 2>&1; then
    echo "$REASONING" | fold -s -w 80 | sed 's/^/  /'
  else
    echo "  $REASONING"
  fi
  echo ""
  echo "---"
  echo ""
  echo "## Evidence (auto-generated)"
  echo ""
  echo "- **Generated:** ${TS}"
  echo "- **Tool:** scope-review-inline.sh (R44 U2/U8, heuristic — NOT an LLM call)"
  echo "- **Draft:** ${DRAFT}"
  echo "- **Brief:** $([ "$BRIEF_EXISTS" = "1" ] && echo "${BRIEF}" || echo "(not generated; scope-review.sh unavailable)")"
  echo ""
  echo "### Citation-graph top hits"
  echo '```'
  if [ -n "$GRAPH_ALL_HITS" ]; then
    echo "$GRAPH_ALL_HITS"
  else
    echo "(graph-query produced no hits or is unavailable)"
  fi
  echo '```'
  echo ""
  echo "### OOS bullets matched"
  if [ -n "$OOS_MATCHED_BULLETS" ]; then
    echo "$OOS_MATCHED_BULLETS"
  else
    echo "_(none)_"
  fi
  echo ""
  echo "### Scope-acknowledgment language in draft"
  if [ "$SCOPE_ACK" = "1" ]; then
    echo '```'
    echo "$SCOPE_ACK_QUOTE"
    echo '```'
  else
    echo "_(no scope-ack language detected)_"
  fi
  echo ""
  echo "---"
  echo ""
  echo "_This file is compatible with \`pre-submit-check.sh\` Check #11 as a"
  echo "fallback to \`.agent-review.md\`. To upgrade to an LLM-level review,"
  echo "dispatch \`${BRIEF}\` via the Task tool and save the result to"
  echo "\`${OUT_DIR}/${BASENAME}.agent-review.md\`._"
} > "$OUT"

echo "[scope-review-inline] → $OUT"
echo "[scope-review-inline] VERDICT: ${VERDICT} (confidence=${CONFIDENCE}, graph_top=${GRAPH_TOP_SCORE}, oos=${OOS_MATCHED_IDS:-none})"

if [ "$VERDICT" = "SAME-CLASS-DIFFERENT-VECTOR" ]; then
  _CITE="${SAMEWS_AUDIT:-$GRAPH_TOP_AUDIT}"
  echo "[scope-review-inline] NEXT: consider ./tools/reframe-same-class.sh ${WS} ${DRAFT} \"${_CITE}\""
fi

exit 0
