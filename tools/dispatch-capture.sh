#!/usr/bin/env bash
# dispatch-capture.sh — persist a dispatched agent's verbatim output to disk
# with a metadata header, and append a row to agent_outputs/INDEX.md.
#
# Usage:
#   cat agent-output.txt | dispatch-capture.sh <workspace> <agent-id> <hypothesis-slug> [--verdict TP|FP|NEEDS-VERIFY]
#
# Closes: issue #132 (agent outputs must be persisted, not left only in chat).
set -euo pipefail

usage() {
  cat <<'EOF' >&2
Usage: cat agent-output.txt | dispatch-capture.sh <workspace> <agent-id> <hypothesis-slug>
         [--verdict VERDICT] [--per-verdict-record [--detector NAME]]

  <workspace>             Absolute path to the audit workspace.
  <agent-id>              Short id for the dispatched agent (e.g. "sonnet-3").
  <hypothesis-slug>       Short slug (kebab-case) describing the hypothesis.
  --verdict VERDICT       Optional: TP | FP | NEEDS-VERIFY (free text also accepted).
                          If omitted, the script grep's stdin for a "VERDICT:" line.
  --per-verdict-record    Issue #146: also parse every (TOP-N:, VERDICT:) pair
                          in the output and call record-triage.sh for each one
                          so per-hypothesis precision lands in the ledger.
  --detector NAME         Detector label recorded with --per-verdict-record
                          (default: the hypothesis-slug).
EOF
  exit 2
}

[ $# -lt 3 ] && usage

WORKSPACE="$1"; shift
AGENT_ID="$1"; shift
SLUG="$1"; shift

VERDICT=""
# Issue #146: per-agent-verdict ledger granularity — when the agent output
# contains multiple `TOP-N:` items each with a `VERDICT:` line, auto-record
# each as its own ledger row via record-triage.sh so fine-grained precision
# data isn't lost. Disabled by default to preserve backward compat; opt-in
# via --per-verdict-record.
PER_VERDICT_RECORD=0
PER_VERDICT_DETECTOR=""
while [ $# -gt 0 ]; do
  case "$1" in
    --verdict) VERDICT="$2"; shift 2 ;;
    --per-verdict-record) PER_VERDICT_RECORD=1; shift ;;
    --detector) PER_VERDICT_DETECTOR="$2"; shift 2 ;;
    -h|--help) usage ;;
    *) echo "Unknown arg: $1" >&2; usage ;;
  esac
done

[ -d "$WORKSPACE" ] || { echo "workspace not found: $WORKSPACE" >&2; exit 1; }

OUT_DIR="$WORKSPACE/agent_outputs"
mkdir -p "$OUT_DIR"

TS="$(date -u +%Y-%m-%dT%H%M%SZ)"

# sanitize agent-id + slug for filename (alnum, -, _)
safe() { printf '%s' "$1" | tr -c 'A-Za-z0-9._-' '-' | sed 's/-\{2,\}/-/g; s/^-\+//; s/-\+$//'; }
AGENT_SAFE="$(safe "$AGENT_ID")"
SLUG_SAFE="$(safe "$SLUG")"

OUT_FILE="$OUT_DIR/${TS}_${AGENT_SAFE}_${SLUG_SAFE}.md"

# Read stdin to a temp file so we can both scan it and embed it.
TMP_IN="$(mktemp -t agentcap.XXXXXX)"
trap 'rm -f "$TMP_IN"' EXIT
cat > "$TMP_IN"

if [ -z "$VERDICT" ]; then
  # Best-effort: look for a VERDICT: line in stdin
  V_LINE="$(grep -m1 -E '^[[:space:]]*VERDICT:' "$TMP_IN" 2>/dev/null || true)"
  if [ -n "$V_LINE" ]; then
    VERDICT="$(printf '%s' "$V_LINE" | sed -E 's/^[[:space:]]*VERDICT:[[:space:]]*//')"
  else
    VERDICT="UNKNOWN"
  fi
fi

# Find a matching brief, if any, for cross-linking.
# We match on the slug OR agent-id; first hit wins.
BRIEF_LINK=""
if [ -d "$OUT_DIR" ]; then
  MATCH="$(ls -1 "$OUT_DIR"/brief_*_*.md 2>/dev/null | grep -E "${SLUG_SAFE}|${AGENT_SAFE}" | head -n 1 || true)"
  if [ -z "$MATCH" ]; then
    # fallback: newest brief at all
    MATCH="$(ls -1t "$OUT_DIR"/brief_*.md 2>/dev/null | head -n 1 || true)"
  fi
  [ -n "$MATCH" ] && BRIEF_LINK="$MATCH"
fi

# ---------- write the capture file ----------
{
  echo "# Agent output — ${SLUG_SAFE}"
  echo
  echo "- **Timestamp:** ${TS}"
  echo "- **Agent-id:** ${AGENT_ID}"
  echo "- **Hypothesis-slug:** ${SLUG}"
  echo "- **Verdict:** ${VERDICT}"
  echo "- **Workspace:** ${WORKSPACE}"
  if [ -n "$BRIEF_LINK" ]; then
    echo "- **Linked brief:** \`${BRIEF_LINK}\`"
  else
    echo "- **Linked brief:** (none found in agent_outputs/)"
  fi
  echo
  echo "---"
  echo
  echo "## Verbatim agent output"
  echo
  cat "$TMP_IN"
} > "$OUT_FILE"

# ---------- append row to INDEX.md ----------
INDEX="$OUT_DIR/INDEX.md"
if [ ! -f "$INDEX" ]; then
  {
    echo "# Agent outputs index"
    echo
    echo "| timestamp | agent-id | hypothesis-slug | verdict | file |"
    echo "|---|---|---|---|---|"
  } > "$INDEX"
fi

# sanitize pipe chars in verdict so the row stays a valid markdown row
VERDICT_CELL="$(printf '%s' "$VERDICT" | tr '|' '/' | tr '\n' ' ')"
REL_FILE="${OUT_FILE#$WORKSPACE/}"
echo "| ${TS} | ${AGENT_ID} | ${SLUG} | ${VERDICT_CELL} | \`${REL_FILE}\` |" >> "$INDEX"

# ---------- Issue #146: per-agent-verdict ledger rows -----------------------
# Parse all (TOP-N, VERDICT) pairs from the output and emit one record-triage
# call per verdict. This replaces the single aggregated-cluster row with
# per-hypothesis granularity so dpper-precision data is preserved.
if [ "$PER_VERDICT_RECORD" = 1 ]; then
  DETECTOR_ARG="${PER_VERDICT_DETECTOR:-$SLUG_SAFE}"
  # Walk the output line-by-line; whenever we see a TOP-N tag, remember it
  # as the current sub-hypothesis slug; whenever we see a VERDICT line,
  # flush a ledger row using the current slug (or the parent slug).
  awk -v slug="$SLUG_SAFE" '
    BEGIN { top = "" }
    /^[[:space:]]*TOP-[0-9A-Za-z]+:/ {
      line = $0
      sub(/^[[:space:]]*TOP-/, "", line); sub(/:.*/, "", line)
      top = line
      next
    }
    /^[[:space:]]*VERDICT:/ {
      v = $0
      sub(/^[[:space:]]*VERDICT:[[:space:]]*/, "", v)
      # Strip down to first word (TP / FP / NEEDS-VERIFY / UNKNOWN)
      split(v, parts, /[[:space:]]+/); kind = parts[1]
      # Normalise NEEDS-VERIFY → UNKNOWN since record-triage only accepts TP/FP/UNKNOWN
      if (kind == "NEEDS-VERIFY" || kind == "NEEDS_VERIFY") kind = "UNKNOWN"
      # Pick severity word if present (Low|Medium|High|Critical)
      sev = ""
      for (i = 2; i <= length(parts); i++) {
        if (parts[i] ~ /severity-/) { sev = parts[i]; sub(/^severity-/, "", sev) }
      }
      tag = top == "" ? slug : slug "-top" top
      printf "%s|%s|%s\n", tag, kind, sev
      top = ""
    }
  ' "$TMP_IN" > "$TMP_IN.rows" 2>/dev/null || true

  ROWS_DUMP="$OUT_DIR/${TS}_${AGENT_SAFE}_${SLUG_SAFE}.rows.tsv"
  : > "$ROWS_DUMP"
  while IFS='|' read -r tag kind sev; do
    [ -z "$tag" ] && continue
    WS_NAME=$(basename "$WORKSPACE")
    # Best-effort: tolerate a missing/failed record-triage.sh (e.g. no PyYAML)
    if bash "$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/record-triage.sh" \
         "$DETECTOR_ARG" "$WS_NAME" "$tag" "$kind" "$sev" >/dev/null 2>&1; then
      echo -e "$DETECTOR_ARG\t$WS_NAME\t$tag\t$kind\t$sev" >> "$ROWS_DUMP"
    else
      echo -e "$DETECTOR_ARG\t$WS_NAME\t$tag\t$kind\t$sev\tSKIPPED" >> "$ROWS_DUMP"
    fi
  done < "$TMP_IN.rows"
  rm -f "$TMP_IN.rows"
fi

echo "$OUT_FILE"
