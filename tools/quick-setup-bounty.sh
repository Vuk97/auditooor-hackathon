#!/usr/bin/env bash
# quick-setup-bounty.sh — One-command bounty workspace bootstrap
#
# Sets up a complete audit workspace from the canonical scaffold:
#   1. Calls setup-workspace.sh for the baseline workspace layout/docs
#   2. Clones target repo (if URL given)
#   3. Runs CCIA for cross-contract analysis
#   4. Runs cross-workspace pattern mapper
#   5. Runs mining prioritizer
#   6. Generates mining briefs
#   7. Initializes workspace state tracker
#   8. Produces setup report
#
# Usage:
#   ./tools/quick-setup-bounty.sh <name> [--repo <git-url>] [--src-dir <dir>]
#   ./tools/quick-setup-bounty.sh polymarket-v2 --repo https://github.com/Polymarket/cniru
#   ./tools/quick-setup-bounty.sh centrifuge-v4 --src-dir ~/downloads/centrifuge

set -uo pipefail

NAME="${1:-}"
REPO_URL=""
SRC_DIR=""

usage() {
    cat <<'EOF'
quick-setup-bounty.sh — One-command bounty workspace bootstrap

Usage:
  ./tools/quick-setup-bounty.sh <name> [--repo <git-url>] [--src-dir <dir>]

Examples:
  ./tools/quick-setup-bounty.sh polymarket-v2 --repo https://github.com/Polymarket/cniru
  ./tools/quick-setup-bounty.sh centrifuge-v4 --src-dir ~/downloads/centrifuge
EOF
}

case "${1:-}" in
    -h|--help)
        usage
        exit 0
        ;;
esac

shift 2>/dev/null || true

while [ $# -gt 0 ]; do
    case "$1" in
        --repo) REPO_URL="$2"; shift 2 ;;
        --src-dir) SRC_DIR="$2"; shift 2 ;;
        *) shift ;;
    esac
done

if [ -z "$NAME" ]; then
    usage
    exit 1
fi

AUDITOOOR_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
AUDITS_DIR="${AUDITS_DIR:-$HOME/audits}"
WS="$AUDITS_DIR/$NAME"

echo "==========================================================================="
echo "  Quick Setup — $NAME"
echo "==========================================================================="
echo ""

# --- Step 1: Start from the canonical scaffold, then add quick-setup extras ---
SCAFFOLD_LOG="$(mktemp)"
if ! bash "$AUDITOOOR_DIR/tools/setup-workspace.sh" "$NAME" "$AUDITS_DIR" >"$SCAFFOLD_LOG" 2>&1; then
    echo "[setup] setup-workspace.sh failed" >&2
    sed -n '1,120p' "$SCAFFOLD_LOG" >&2
    rm -f "$SCAFFOLD_LOG"
    exit 1
fi
rm -f "$SCAFFOLD_LOG"

mkdir -p "$WS"/{src,submissions/staging,submissions/clean,submissions/packaged,submissions/engage_candidates/clean,agent_outputs,poc-tests,cold_reads,scope_review,swarm/mining_briefs}

if [ ! -f "$WS/OOS_CHECKLIST.md" ]; then
cat > "$WS/OOS_CHECKLIST.md" <<'EOF'
# Out-of-Scope Checklist

- [ ] Centralization risks (admin can add/remove other admins) — by design
- [ ] Front-running / MEV — out of scope
- [ ] Gas optimization — out of scope
- [ ] Code style / formatting — out of scope
- [ ] Issues in dependencies (OpenZeppelin, Solmate, etc.) — out of scope unless directly exploitable

## Program-Specific OOS
[Fill in from bounty terms]
EOF
fi

if [ ! -f "$WS/SEVERITY_CAPS.md" ]; then
cat > "$WS/SEVERITY_CAPS.md" <<'EOF'
# Severity Caps

| Severity | Max Payout | Notes |
|---|---|---|
| Critical | $X | Direct fund theft, permanent freezing |
| High | $Y | Significant fund loss, protocol halt |
| Medium | $Z | State corruption, DOS |
| Low | $W | Edge cases, theoretical |
EOF
fi

echo "[setup] Canonical scaffold created at: $WS"

# --- Step 2: Clone or link source ---
if [ -n "$REPO_URL" ]; then
    echo "[setup] Cloning $REPO_URL ..."
    git clone "$REPO_URL" "$WS/src" 2>&1 | tail -3
elif [ -n "$SRC_DIR" ]; then
    echo "[setup] Linking $SRC_DIR → $WS/src"
    if [ -d "$WS/src" ] && [ -z "$(ls -A "$WS/src" 2>/dev/null)" ]; then
        rmdir "$WS/src"
    fi
    ln -s "$(cd "$SRC_DIR" && pwd)" "$WS/src"
else
    echo "[setup] No --repo or --src-dir provided. Populate $WS/src manually."
fi

# --- Step 3: Run CCIA ---
echo ""
echo "[setup] Running CCIA ..."
python3 "$AUDITOOOR_DIR/tools/ccia.py" "$WS" --out "$WS/ccia_report.json" --json 2>&1 | tail -5

# --- Step 4: Cross-workspace pattern mapper ---
echo ""
echo "[setup] Running cross-workspace pattern mapper ..."
python3 "$AUDITOOOR_DIR/tools/cross-ws-pattern-mapper.py" --audits-dir "$AUDITS_DIR" --generate-ccia --out "$WS/cross_ws_patterns.md" 2>&1 | tail -5

# --- Step 5: Mining prioritizer ---
echo ""
echo "[setup] Running mining prioritizer ..."
python3 "$AUDITOOOR_DIR/tools/mining-prioritizer.py" "$WS" --top 20 --json > "$WS/mining_priorities.json" 2>&1 | tail -10

# --- Step 6: Generate mining briefs ---
echo ""
echo "[setup] Generating mining briefs ..."
python3 "$AUDITOOOR_DIR/tools/mining-brief-generator.py" "$WS" --top 10 --out-dir "$WS/swarm/mining_briefs" 2>&1 | tail -5

# --- Step 7: Initialize workspace state ---
echo ""
echo "[setup] Initializing workspace state ..."
python3 "$AUDITOOOR_DIR/tools/workspace-state.py" init "$WS" --name "$NAME" 2>/dev/null || true

# --- Step 8: Generate setup report ---
REPORT="$WS/setup-report.md"
cat > "$REPORT" <<EOF
# Setup Report — $NAME

**Generated:** $(date -u +"%Y-%m-%dT%H:%M:%SZ")
**Workspace:** $WS

## Structure
\`\`\`
$WS/
  src/                    # Source code
  SCOPE.md                # Placeholder or fetched bounty scope
  scope.json              # Machine-readable scope metadata
  STATUS.md               # Workspace status / confirmed findings summary
  submissions/
    staging/              # Drafts ready for pre-submit
    clean/                # Triager-clean renders
    packaged/             # Review bundles from submission-packager.py
    engage_candidates/
      clean/              # Triager-clean engage candidate renders
  agent_outputs/          # Agent briefs and outputs
  poc-tests/              # Proof of concept tests
  cold_reads/             # Manual cold-read notes
  scope_review/           # Scope review artifacts
  swarm/mining_briefs/    # Generated mining briefs
  AUDIT.md                # Audit plan / notes
  OOS_CHECKLIST.md        # Out-of-scope items (placeholder until extract-oos)
  SEVERITY_CAPS.md        # Severity caps (placeholder until extract-oos)
\`\`\`

## Generated Artifacts
- CCIA Report: \`$WS/ccia_report.json\`
- Cross-WS Patterns: \`$WS/cross_ws_patterns.md\`
- Mining Priorities: \`$WS/mining_priorities.json\`
- Mining Briefs: \`$WS/swarm/mining_briefs/\`

## Next Steps
1. Review CCIA attack angles in \`ccia_report.json\`
2. Review mining briefs in \`swarm/mining_briefs/\`
3. Replace the placeholder \`SCOPE.md\` with the real bounty program text if needed
4. Run the canonical orchestration path: \`make engage WORKSPACE=$WS\`
5. Or manually investigate top-priority angles

## Quick Commands
\`\`\`bash
# Run the canonical engagement chain
make engage WORKSPACE=$WS

# Preview the stage plan without executing it
python3 $AUDITOOOR_DIR/tools/engage.py --workspace $WS --dry-run --summary

# Check workspace state
python3 $AUDITOOOR_DIR/tools/workspace-state.py get $WS

# Generate draft from angle
python3 $AUDITOOOR_DIR/tools/auto-draft-generator.py $WS --angle-id A-REENT --contract <Contract> --with-poc
\`\`\`
EOF

echo ""
echo "==========================================================================="
echo "  Setup complete — $NAME"
echo "==========================================================================="
echo ""
echo "  Workspace:     $WS"
echo "  Report:        $REPORT"
echo "  CCIA:          $WS/ccia_report.json"
echo "  Briefs:        $WS/swarm/mining_briefs/"
echo ""
echo "  Next: Review mining briefs, then run:"
echo "    make engage WORKSPACE=$WS"
echo ""
