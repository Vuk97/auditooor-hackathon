#!/usr/bin/env bash
# solodit-context.sh — wire MCP Solodit into the triage hot-path (Issue #105).
#
# For a given scan hit (detector + contract + function), produces a Solodit
# query brief that the main conversation can execute via MCP to pre-answer
# "is this class a known protocol pattern?" before human triage.
#
# This tool does NOT call Solodit directly — Solodit access lives in the MCP
# server wired into the main Claude conversation. This tool produces the
# STRUCTURED QUERY that the assistant's next turn should execute via
# mcp__solodit__search_findings.
#
# Usage:
#   ./tools/solodit-context.sh <detector-slug> [severity] [protocol-type]
#
# Example:
#   ./tools/solodit-context.sh callback-reentrancy-no-guard HIGH lending
#
# Output: a JSON-ish block with recommended search params.

set -u
DET="${1:-}"
SEV="${2:-}"
PROTO="${3:-}"

if [ -z "$DET" ]; then
  echo "usage: $0 <detector-slug> [severity] [protocol-type]" >&2
  exit 2
fi

# Map detector slug → Solodit search tags (heuristic)
case "$DET" in
  *reentrancy*)
    TAGS='["Reentrancy"]'
    KW="$(echo "$DET" | tr '-' ' ')"
    ;;
  *role-grant*|*self-admin*)
    TAGS='["Access Control"]'
    KW="role grant divergence"
    ;;
  *storage-packing*|*downcast*|*uint*)
    TAGS='["Downcast", "Integer Overflow"]'
    KW="storage packing downcast"
    ;;
  *abi-encode-packed*)
    TAGS='["Hash Collision"]'
    KW="abi.encodePacked"
    ;;
  *oracle*|*price*)
    TAGS='["Oracle", "Price Manipulation"]'
    KW="oracle manipulation"
    ;;
  *flashloan*)
    TAGS='["Flash Loan"]'
    KW="flashloan"
    ;;
  *signature*|*sig-replay*|*ecrecover*)
    TAGS='["Signature", "Replay"]'
    KW="signature replay"
    ;;
  *vault*|*4626*|*share*)
    TAGS='["ERC4626", "Share Price"]'
    KW="share price manipulation"
    ;;
  *fee*|*rate*|*accrual*)
    TAGS='["Fee", "Accounting"]'
    KW="fee accrual"
    ;;
  *)
    TAGS="[]"
    KW="$(echo "$DET" | tr '-' ' ')"
    ;;
esac

cat <<EOF
# Solodit pre-triage query for detector \`$DET\`

## Recommended MCP call

\`\`\`
mcp__solodit__search_findings
  keywords: "$KW"
  tags: $TAGS
  severity: ${SEV:+[\"$SEV\"]}
  page_size: 10
  sort_by: Quality
\`\`\`

## Why

Before spending human/agent tokens on triaging this class, check whether
Solodit (17k real audits) already documents this exact pattern as:
  - frequently-paid (then our hit is likely TP)
  - frequently-rejected / disputed (then likely FP on this architecture)
  - never-seen (then novel — prioritize drill)

## How to interpret results

- ≥3 paid findings with similar shape → high TP prior
- ≥3 DUPE / DISPUTED findings with similar shape → high FP prior
- Zero hits → novel, drill recommended

## Feed back into ledger

After reading Solodit results, tag the triage with the prior-bias:

\`\`\`
./tools/record-triage.sh $DET <workspace> <finding-id> <TP|FP|UNKNOWN>
# comment: solodit-prior=<paid|dupe|novel>
\`\`\`
EOF
