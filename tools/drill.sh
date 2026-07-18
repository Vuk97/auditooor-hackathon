#!/usr/bin/env bash
# drill.sh — dedicated Phase-3 drill sidecar (Issue #121).
#
# After auto-triage.sh emits NEEDS-VERIFY clusters, or a STRIDE attack-tree
# surfaces a hypothesis that needs source-level confirmation, the operator
# invokes drill.sh with a structured (contract, hypothesis) pair.
#
# drill.sh is a thin composition of existing pieces (intentionally — it is
# the "sidecar" split from #105 so the pipeline is discoverable by name):
#
#   1. Generates a brief via dispatch-brief.sh (auto-pulls OOS + CAPS +
#      PRIOR_CONCERNS + DIGEST attacker-angles + first 300 lines of source).
#   2. Prints a paste-ready Task block the operator feeds into Claude Code.
#   3. After the agent returns, `drill.sh capture <agent-out.txt> <agent-id>`
#      routes stdout into dispatch-capture.sh so the verdict lands on disk
#      and in agent_outputs/INDEX.md.
#
# Usage:
#   drill.sh brief   <ws> <contract.sol> <hypothesis-text>
#   drill.sh capture <ws> <agent-id> <slug> [--verdict TP|FP|NEEDS-VERIFY] < agent-output.txt
#
# Exit codes:
#   0 — brief written or capture persisted
#   2 — usage / missing files
set -euo pipefail

AUDITOOOR_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

usage() {
  cat <<'EOF' >&2
Usage:
  drill.sh brief   <workspace> <contract.sol> <hypothesis-text>
  drill.sh capture <workspace> <agent-id> <slug> [--verdict V] < agent-output.txt

Examples:
  ./tools/drill.sh brief ~/audits/centrifuge src/core/Hub.sol \
    "initializeHolding emits before auth check — can unauthorized caller bootstrap state?"

  cat sonnet-reply.txt | \
    ./tools/drill.sh capture ~/audits/centrifuge a12bc34 hub-init-auth \
      --verdict NEEDS-VERIFY
EOF
  exit 2
}

[ $# -lt 1 ] && usage
MODE="$1"; shift

case "$MODE" in
  brief)
    [ $# -lt 3 ] && usage
    WS="$1"; CONTRACT="$2"; HYPO="$3"
    [ -d "$WS" ]       || { echo "workspace not found: $WS" >&2; exit 2; }
    [ -f "$CONTRACT" ] || { echo "contract not found: $CONTRACT" >&2; exit 2; }

    BRIEF_FILE="$("$AUDITOOOR_DIR/tools/dispatch-brief.sh" "$WS" "$CONTRACT" "$HYPO")"
    echo "[drill] brief written to: $BRIEF_FILE" >&2

    # Paste-ready Task block for the operator.
    cat <<EOT
---
### Task (paste into Claude Code)

You are a drill agent (Phase 3). Open the brief at:

  $BRIEF_FILE

Follow every instruction under "Mandatory reading" and "Task".
Emit the VERDICT line EXACTLY in the required format.

After the agent replies, capture with:

  cat <agent-reply.txt> | \\
    $AUDITOOOR_DIR/tools/drill.sh capture \\
      "$WS" <agent-id> $(basename "${CONTRACT%.sol}" | tr 'A-Z' 'a-z')-drill
---
EOT
    ;;

  capture)
    [ $# -lt 3 ] && usage
    # Pass-through to dispatch-capture.sh (stdin flows through).
    exec "$AUDITOOOR_DIR/tools/dispatch-capture.sh" "$@"
    ;;

  -h|--help|help)
    usage
    ;;
  *)
    echo "unknown subcommand: $MODE" >&2
    usage
    ;;
esac
