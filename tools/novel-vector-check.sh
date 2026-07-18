#!/usr/bin/env bash
# novel-vector-check.sh — classify a draft finding against prior-audit findings
# by ATTACK VECTOR (not just class). Outputs one of:
#
#   NOVEL       — no prior-audit match on class OR vector → submit
#   SAME-CLASS-DIFFERENT-VECTOR — prior audit raised the class, but your attack
#                                 path / entry / user-impact is distinct → submit
#                                 with explicit "DIFFERENT VECTOR than §X.Y.Z" framing
#   SAME-VECTOR — prior audit raised the exact same attack path → reject as dupe
#   ACK-OOS     — prior audit raised AND protocol acknowledged as by-design → reject
#
# Usage:
#   ./tools/novel-vector-check.sh <workspace> <draft.md>
#
# Depends on: prior_audits/DIGEST_*.md + SCOPE.md + OOS_CHECKLIST.md existing.
# The tool reads the draft's "Summary" and "Vulnerable code" sections, extracts
# keyword fingerprints, and greps the prior-audit corpus for vector matches.
#
# Output goes to <workspace>/scope_review/<basename>.novel-vector.md with a
# full evidence trail (prior-audit citations + verdict + submission guidance).

set -u
WS="${1:-}"
DRAFT="${2:-}"

if [ -z "$WS" ] || [ ! -d "$WS" ] || [ -z "$DRAFT" ] || [ ! -f "$DRAFT" ]; then
  echo "usage: $0 <workspace> <draft.md>" >&2
  exit 2
fi

OUT_DIR="$WS/scope_review"
mkdir -p "$OUT_DIR"
BASENAME=$(basename "$DRAFT" .md)
OUT="$OUT_DIR/${BASENAME}.novel-vector.md"

# Collect prior-audit corpus text
AUDIT_DIR="$WS/prior_audits"
if [ ! -d "$AUDIT_DIR" ]; then
  echo "[novel-vector-check] WARN: $AUDIT_DIR missing — no prior audits to compare" >&2
fi

# Extract fingerprint keywords from draft
DRAFT_TXT=$(cat "$DRAFT")
FINGERPRINT=$(echo "$DRAFT_TXT" | tr -s '[:space:]' '\n' \
  | grep -oE '[A-Za-z_][A-Za-z0-9_.]{4,}' \
  | grep -viE '^(the|and|this|that|with|from|into|have|been|will|they|when|then|each|your|most|more|only|such|some|also|very|must|many|both|what|than|these|other|which|make|like|time|even|still|same|very|just|over|here|kind|being|above|below|after|before|where|about|under|while|their|would|should|could|first|second|third|their|there|every|order|event|state|value|check)$' \
  | sort -u | head -40 | tr '\n' '|' | sed 's/|$//')

# Hunt mode 1: citation-graph similarity (R43 U6).
# Falls back to raw grep on $AUDIT_DIR/*.txt only if graph-query is unavailable
# or returns no results.
HERE_DIR="$(cd "$(dirname "$0")" && pwd)"
GRAPH_QUERY="$HERE_DIR/graph-query.sh"
GRAPH_FILE="$HERE_DIR/../reference/citation_graph.yaml"
GRAPH_TOP_SCORE=""
GRAPH_TOP_NODE=""
GRAPH_HITS_RAW=""
GRAPH_AVAILABLE=0

if [ -x "$GRAPH_QUERY" ] && [ -f "$GRAPH_FILE" ]; then
  GRAPH_AVAILABLE=1
  GRAPH_HITS_RAW=$("$GRAPH_QUERY" --similar-to "$DRAFT" --limit 5 2>/dev/null || true)
  GRAPH_TOP_SCORE=$(echo "$GRAPH_HITS_RAW" | grep -oE 'score=\s*[0-9]+' | head -1 | grep -oE '[0-9]+')
  GRAPH_TOP_NODE=$(echo "$GRAPH_HITS_RAW" | grep -A1 '^\[score=' | head -2 | tail -1 | sed 's/^[[:space:]]*//')
fi

CLASS_HITS=""
if [ "$GRAPH_AVAILABLE" = "1" ] && [ -n "$GRAPH_TOP_SCORE" ] && [ "$GRAPH_TOP_SCORE" -gt 0 ]; then
  # Format graph hits for the report block
  CLASS_HITS=$(echo "$GRAPH_HITS_RAW" | awk '/^\[score=/{print}')
elif [ -d "$AUDIT_DIR" ] && [ -n "$FINGERPRINT" ]; then
  # Fallback: raw grep over prior-audit .txt corpus
  CLASS_HITS=$(grep -riEl "$FINGERPRINT" "$AUDIT_DIR"/*.txt 2>/dev/null | head -5)
fi

# Hunt mode 2: OOS bullet overlap
OOS_HITS=""
if [ -f "$WS/OOS_CHECKLIST.md" ] && [ -n "$FINGERPRINT" ]; then
  OOS_HITS=$(grep -iE "$FINGERPRINT" "$WS/OOS_CHECKLIST.md" 2>/dev/null | head -5)
fi

# Hunt mode 3: scope-exclusion language (centralization, admin, operator-trust)
ACK_HITS=""
if [ -f "$WS/SCOPE.md" ]; then
  ACK_TERMS="centralization|admin|privileged|trusted by design|known.*by design|acknowledged|unfixed.*previous audit|operator is trusted"
  # See if the draft's flavor matches any of these exclusion phrases
  DRAFT_LOWER=$(echo "$DRAFT_TXT" | tr 'A-Z' 'a-z')
  for phrase in "admin" "operator" "centralization" "privileged address" "access control"; do
    if echo "$DRAFT_LOWER" | grep -qE "\b${phrase}\b.*(attack|exploit|abus|requir|captur|malicious|cause)"; then
      SCOPE_QUOTE=$(grep -iE "$ACK_TERMS" "$WS/SCOPE.md" 2>/dev/null | head -3)
      ACK_HITS="$phrase → $SCOPE_QUOTE"
      break
    fi
  done
fi

# Verdict logic
VERDICT="NOVEL"
RATIONALE="No prior-audit hit on extracted fingerprint + no OOS-keyword overlap + no centralization smell."

# R45 bugfix (Bug 5): only apply the ACK-OOS smell-word override when:
#   (1) there is NO citation-graph match (otherwise trust the graph — a
#       specific prior-finding citation outweighs generic "admin"/"operator"
#       language), AND
#   (2) the smell-word was found next to an attack verb (the ACK_HITS regex
#       already enforces this — we just re-check it's non-empty here).
# Prior behaviour: ACK-OOS-LIKELY was applied unconditionally when ACK_HITS
# was non-empty, which buried strong SAME-CLASS-DIFFERENT-VECTOR graph signal
# under a coarse "contains the word admin" flag.
GRAPH_MATCH_PRESENT=0
if [ "$GRAPH_AVAILABLE" = "1" ] && [ -n "$GRAPH_TOP_SCORE" ] && [ "$GRAPH_TOP_SCORE" -gt 0 ]; then
  GRAPH_MATCH_PRESENT=1
fi

if [ -n "$ACK_HITS" ] && [ "$GRAPH_MATCH_PRESENT" = "0" ]; then
  VERDICT="ACK-OOS-LIKELY"
  RATIONALE="Draft contains centralization/admin/operator-trust language near an attack verb and no citation-graph match was produced. Operator review required before filing."
fi

if [ -n "$CLASS_HITS" ]; then
  # If graph-query produced a score, use it to refine the verdict.
  # Graph signal OVERRIDES ACK-OOS-LIKELY when score is very high (SAME-VECTOR) —
  # a specific prior-finding citation is more actionable than generic OOS smell.
  #   score >= 15 → SAME-VECTOR (very likely dupe — same targets, same mechanism keywords)
  #   score  5-14 → SAME-CLASS-DIFFERENT-VECTOR (class match, vector-distinct review needed)
  #   score  1-4  → weak match, keep existing verdict but append hint
  if [ "$GRAPH_AVAILABLE" = "1" ] && [ -n "$GRAPH_TOP_SCORE" ]; then
    if [ "$GRAPH_TOP_SCORE" -ge 15 ]; then
      VERDICT="SAME-VECTOR"
      RATIONALE="Citation-graph similarity score ${GRAPH_TOP_SCORE} against prior finding: ${GRAPH_TOP_NODE}. This is a probable dupe — contract + function + mechanism keywords align tightly. Open the cited finding and verify attack-path-vs-path before filing. Default: reject."
    elif [ "$GRAPH_TOP_SCORE" -ge 5 ] && [ "$VERDICT" = "NOVEL" ]; then
      VERDICT="SAME-CLASS-DIFFERENT-VECTOR"
      RATIONALE="Citation-graph similarity score ${GRAPH_TOP_SCORE} against prior finding: ${GRAPH_TOP_NODE}. Class-level overlap detected but your ATTACK VECTOR may be distinct. Submit only with explicit 'DIFFERENT VECTOR than <prior>' framing documenting how the entry point / user impact / privilege requirement differs."
    elif [ "$VERDICT" = "NOVEL" ]; then
      VERDICT="SAME-CLASS-NEEDS-VECTOR-REVIEW"
      RATIONALE="Weak citation-graph match (score ${GRAPH_TOP_SCORE}): ${GRAPH_TOP_NODE}. Likely novel but double-check the prior finding's attack path before filing."
    fi
  elif [ "$VERDICT" = "NOVEL" ]; then
    VERDICT="SAME-CLASS-NEEDS-VECTOR-REVIEW"
    RATIONALE="Fingerprint matches keywords present in prior audits: $CLASS_HITS. NOT automatically a dupe — operator must verify attack-path-vs-path. If vector is distinct, submit with 'DIFFERENT VECTOR than §X.Y.Z' framing."
  fi
fi

# Emit report
cat > "$OUT" <<REPORT
# Novel-vector scope check — $BASENAME

Generated: $(date -u +%Y-%m-%dT%H:%M:%SZ)

## Verdict: $VERDICT

$RATIONALE

## Evidence

### Fingerprint extracted from draft
\`\`\`
$FINGERPRINT
\`\`\`

### Prior-audit hits (citation-graph similarity)
$(if [ "$GRAPH_AVAILABLE" = "1" ]; then
    if [ -n "$GRAPH_HITS_RAW" ] && echo "$GRAPH_HITS_RAW" | grep -q '^\[score='; then
      echo '```'
      echo "$GRAPH_HITS_RAW"
      echo '```'
    else
      echo "_(graph loaded but no similarity hits above threshold)_"
    fi
  else
    if [ -n "$CLASS_HITS" ]; then echo "$CLASS_HITS" | sed 's|^|- |'; else echo "_(graph unavailable — no prior-audit .txt hits either)_"; fi
  fi)

### OOS_CHECKLIST.md keyword overlap
$(if [ -n "$OOS_HITS" ]; then echo "$OOS_HITS"; else echo "_(no overlap)_"; fi)

### SCOPE.md exclusion-language smell
$(if [ -n "$ACK_HITS" ]; then echo "$ACK_HITS"; else echo "_(no smell)_"; fi)

## Operator decision matrix

- **NOVEL** → proceed to pre-submit-check.sh
- **SAME-VECTOR** → citation-graph flagged a high-similarity prior finding (score ≥ 15). Default action: reject. Only submit if you can prove the prior-audit attack path is genuinely different (rare).
- **SAME-CLASS-DIFFERENT-VECTOR** → citation-graph flagged moderate similarity (score 5–14). Open the cited prior finding; if ATTACK PATH is distinct (different entry point / user impact / privilege requirement), submit with explicit "DIFFERENT VECTOR than <prior>" framing.
- **SAME-CLASS-NEEDS-VECTOR-REVIEW** → weak graph hit or fallback grep match. Manually verify attack-path-vs-path before filing.
- **ACK-OOS-LIKELY** → re-read SCOPE.md OOS list; if the draft truly fits an OOS bullet, move to \`submissions/_oos_rejected/\`. If operator disagrees, proceed but flag risk.

## Next steps

\`\`\`bash
./tools/pre-submit-check.sh "$DRAFT"
\`\`\`

Run only after this file's verdict is NOVEL or operator has confirmed SAME-CLASS-DIFFERENT-VECTOR framing is defensible.
REPORT

echo "[novel-vector-check] → $OUT"
echo "[novel-vector-check] VERDICT: $VERDICT"
exit 0
