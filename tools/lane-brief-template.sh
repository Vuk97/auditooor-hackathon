#!/usr/bin/env bash
# lane-brief-template.sh - Generate a canonical hacker-mindset lane brief.
#
# Capability Gap #28 deliverable: codifies the Layer-1 hacker MCP stack
# (per ~/.claude/CLAUDE.md §1b) as a re-usable brief generator. Operators
# and orchestrators call this script to produce a ready-to-pass prompt
# skeleton for the Agent tool. The lane-specific goal / method / files
# are appended by the caller.
#
# Usage:
#   bash tools/lane-brief-template.sh \
#     --lane-id <id> --lane-type <hunt|drill|comp|fuzz|filing|tool-build> \
#     --workspace <ws> [--severity <LOW|MEDIUM|HIGH|CRITICAL>] \
#     [--attack-class <class>] [--source-path <path>] \
#     [--output <prompt.md>] [--quiet]
#
# Behavior:
# - lane-type=hunt|drill|comp|fuzz -> full 16-callable Layer-1 stack
# - lane-type=tool-build -> minimal stack (resume + capability_inventory)
# - lane-type=filing -> filing stack (resume + invariant + finalization)
#
# Companion: docs/HACKER_LANE_BRIEF_TEMPLATE.md (the canonical reference).
#
# Tests: tools/tests/test_lane_brief_template.sh

set -uo pipefail

LANE_ID=""
LANE_TYPE=""
WORKSPACE=""
SEVERITY="MEDIUM"
ATTACK_CLASS=""
SOURCE_PATH=""
OUTPUT=""
QUIET=0

print_usage() {
  sed -n '2,32p' "$0"
}

while [ $# -gt 0 ]; do
  case "$1" in
    --lane-id) LANE_ID="$2"; shift 2 ;;
    --lane-type) LANE_TYPE="$2"; shift 2 ;;
    --workspace) WORKSPACE="$2"; shift 2 ;;
    --severity) SEVERITY="$2"; shift 2 ;;
    --attack-class) ATTACK_CLASS="$2"; shift 2 ;;
    --source-path) SOURCE_PATH="$2"; shift 2 ;;
    --output) OUTPUT="$2"; shift 2 ;;
    --quiet) QUIET=1; shift ;;
    --help|-h) print_usage; exit 0 ;;
    *) echo "[lane-brief-template] unknown arg: $1" >&2; exit 1 ;;
  esac
done

if [ -z "$LANE_ID" ] || [ -z "$LANE_TYPE" ] || [ -z "$WORKSPACE" ]; then
  echo "[lane-brief-template] missing required arg(s); see --help" >&2
  exit 1
fi

case "$LANE_TYPE" in
  hunt|drill|comp|fuzz|filing|tool-build) ;;
  *)
    echo "[lane-brief-template] invalid --lane-type: $LANE_TYPE" >&2
    echo "  valid: hunt|drill|comp|fuzz|filing|tool-build" >&2
    exit 1
    ;;
esac

# Default attack-class and source-path placeholders if not supplied.
[ -z "$ATTACK_CLASS" ] && ATTACK_CLASS="<ATTACK_CLASS>"
[ -z "$SOURCE_PATH" ] && SOURCE_PATH="<PRIMARY_SOURCE_PATH>"

# Compose to a temp file then optionally relocate to --output.
TMPOUT="$(mktemp -t lane-brief.XXXXXX)"
trap 'rm -f "$TMPOUT"' EXIT

emit_header() {
  cat <<EOF
# Lane brief: $LANE_ID ($LANE_TYPE)

Workspace: $WORKSPACE
Severity ceiling: $SEVERITY
Lane type: $LANE_TYPE

EOF
}

emit_layer1_foundation() {
  cat <<EOF
## Section 1 - MCP-first recall (mandatory before any code / source read)

\`\`\`bash
cd $WORKSPACE

# --- A. Foundation context (always-on) -----------------------------------
python3 tools/vault-mcp-server.py --call vault_resume_context \\
  --args '{"workspace_path":"$WORKSPACE","limit":4}'
python3 tools/vault-mcp-server.py --call vault_known_dead_ends \\
  --args '{"workspace_path":"$WORKSPACE","limit":5}'
python3 tools/vault-mcp-server.py --call vault_invariant_library \\
  --args '{"workspace_path":"$WORKSPACE","limit":5}'
python3 tools/vault-mcp-server.py --call vault_capability_inventory \\
  --args '{"filter":{"lane_type":"$LANE_TYPE"},"limit":15}'
python3 tools/vault-mcp-server.py --call vault_lane_cooldown_check \\
  --args '{"workspace_path":"$WORKSPACE","lane_id":"$LANE_ID"}'
EOF
}

emit_layer1_hacker_stack() {
  cat <<EOF

# --- B. Hacker-mindset stack ($LANE_TYPE lane) ----------------------------
# Ranked hacker-mindset context (Phase NEG):
python3 tools/vault-mcp-server.py --call vault_brain_prime_context \\
  --args '{"workspace_path":"$WORKSPACE","limit":10}'

# Proven attack-chain seeds:
python3 tools/vault-mcp-server.py --call vault_hackerman_chain_candidates \\
  --args '{"workspace_path":"$WORKSPACE","limit":10}'
python3 tools/vault-mcp-server.py --call vault_hackerman_detector_relationships \\
  --args '{"workspace_path":"$WORKSPACE","limit":10}'
python3 tools/vault-mcp-server.py --call vault_hackerman_exploit_predicates \\
  --args '{"workspace_path":"$WORKSPACE","limit":10}'
python3 tools/vault-mcp-server.py --call vault_hackerman_novel_vector_context \\
  --args '{"workspace_path":"$WORKSPACE","limit":10}'

# Per-lane attacker-memory pull (the actual brief generator):
python3 tools/vault-mcp-server.py --call vault_hacker_brief_for_lane_v3 \\
  --args '{"workspace_path":"$WORKSPACE","lane_id":"$LANE_ID","limit":10}'

# Composition / multi-step chains:
python3 tools/vault-mcp-server.py --call vault_chained_attack_plan_context \\
  --args '{"workspace_path":"$WORKSPACE","limit":5}'

# Adversarial differential hypotheses (cold-read coverage):
python3 tools/vault-mcp-server.py --call vault_adversarial_hypothesis_differential \\
  --args '{"source_path":"$SOURCE_PATH","max_functions":20}'

# Attack class taxonomy + evidence:
python3 tools/vault-mcp-server.py --call vault_attack_class_taxonomy \\
  --args '{"limit":20}'
python3 tools/vault-mcp-server.py --call vault_attack_class_evidence_v3 \\
  --args '{"attack_class":"$ATTACK_CLASS","limit":10}'

# Per-function attacker-mindset:
python3 tools/vault-mcp-server.py --call vault_function_mindset \\
  --args '{"workspace_path":"$WORKSPACE","limit":5}'
EOF
}

emit_layer1_filing_stack() {
  cat <<EOF

# --- B. Filing-lane stack -----------------------------------------------
# Promotion-bound context (originality + finalization manifest):
python3 tools/vault-mcp-server.py --call vault_finalization_context \\
  --args '{"workspace_path":"$WORKSPACE","limit":5}'
python3 tools/vault-mcp-server.py --call vault_originality_context \\
  --args '{"workspace_path":"$WORKSPACE","limit":5}'
python3 tools/vault-mcp-server.py --call vault_dupe_rejection_context \\
  --args '{"workspace_path":"$WORKSPACE","limit":5}'
EOF
}

emit_layer1_close() {
  cat <<'EOF'
```

**Cooldown gate (A1 discipline)**: if `vault_lane_cooldown_check` shows
this lane was DROPPED in the last 3 iterations with no trigger-state
change, REFUSE to proceed. Emit `cooldown-refusal:<LANE_ID>` and stop.
EOF
}

emit_pathspec_section() {
  cat <<EOF

## Section 2 - Pathspec register (R36 / CODEX-3)

Register the LITERAL files this lane will touch (no glob patterns):

\`\`\`bash
python3 tools/agent-pathspec-register.py register \\
  --lane $LANE_ID \\
  --files <comma,separated,LITERAL,file,paths>
\`\`\`

Per CODEX-3, the \`--files\` value is a comma-separated list of CONCRETE
file paths. Patterns like \`dir/**\` are rejected at registration time.
EOF
}

emit_goal_scope_section() {
  cat <<EOF

## Section 3 - Goal + scope (FILL IN)

- Target component: <file:line range or module name>
- Hypothesis: <attack class / invariant violation being tested>
- Severity ceiling: $SEVERITY (must cite verbatim rubric row per R52)
- OOS check: <confirm surface is in-scope per SCOPE.md>

### Section 3a - Brief-time OOS / AI-FP / known-issue preflight (CAP-GAP-93)

Run this BEFORE source drilling and paste the verdict into your notes:

\`\`\`bash
python3 tools/dispatch_oos_preflight.py \\
  --workspace $WORKSPACE \\
  --candidate-id "$LANE_ID" \\
  --severity "$SEVERITY" \\
  --candidate-text "<hypothesis + target component + detector cluster>" \\
  --render-md
\`\`\`

If it matches BUG_BOUNTY.md / SEVERITY.md / SCOPE.md / prior_audits clauses,
first prove an extension-distinct argument with file:line or PoC evidence.
If that proof is missing, stop early with \`VERDICT: OOS <clause>\`.
EOF
}

emit_method_section() {
  cat <<'EOF'

## Section 4 - Method (orient -> drill -> PoC -> file)

1. **Orient**: read the engage report cluster / live target report row.
   Do NOT read source files end-to-end. Cross-check against
   `vault_known_dead_ends` and the Section 3a CAP-GAP-93 preflight.
2. **Drill**: open only the file:line cited by the engage cluster and
   the Layer-1.B hacker callables.
3. **PoC**: build a minimal harness on a real backend (R30). Avoid
   timing shims (R20), single-wallet multi-role harnesses (R44),
   in-process microbenches for production-grade rubric lines (R18/R19).
4. **File**: stage to `submissions/staging/<slug>/<slug>.md`. Never
   promote to `paste_ready/` without operator authorization (L34).
EOF
}

emit_discipline_section() {
  cat <<'EOF'

## Section 5 - Discipline checklist (verbatim)

- **L34**: no draft-file edits under `submissions/<status>/<slug>/<slug>.md`
  without per-draft operator authorization. Use
  `tools/l34-path-classifier.py <path> --json` if uncertain.
- **R36**: stage with EXPLICIT per-file pathspec. Forbidden:
  `git add -A` / `git add .` / `git add <dir>/` / `git commit -a`.
- **R55**: NO destructive git ops (`git reset --hard`, `git checkout --`,
  `git clean -f`, `git stash drop`) while sibling lanes have uncommitted
  edits.
- **R37**: corpus emits MUST set first-class `verification_tier`.
- **R60**: HIGH+ function-defect findings need reachability proof from a
  user-callable entrypoint.
- **R47 / R53**: HIGH+ findings must scan `prior_audits/` (R53) and
  external acknowledgement catalogs (R47).
EOF
}

# r36-rebuttal: lane-ENUM-FIX-NEGATIVE-CLOSED-WITH-OBSERVATION registered via tools/agent-pathspec-register.py
emit_reply_section() {
  cat <<EOF

## Section 6 - Required reply (verbatim labels)

\`\`\`
== LANE REPLY ==
lane_id: $LANE_ID
verdict: <PASTE-READY|HELD-PENDING-EVIDENCE|NEGATIVE-CLOSED|NEGATIVE-CLOSED-WITH-OBSERVATION-FOR-EXISTING-BUNDLE|OOS|PASS|NEGATIVE|BLOCKED|cooldown-refusal>
context_pack_id: <from Layer-1 recall>
context_pack_hash: <from Layer-1 recall>
files_touched: <comma,separated,LITERAL,file,paths>
test_pass_count: <int or N/A>
report_path: reports/v3_iter_<date>/lane_$LANE_ID/results.md
notes: <1-3 sentences on what worked / didn't>
\`\`\`

\`files_touched\` MUST equal the pathspec registered in Section 2 (or
be a strict subset). Diverging is an R36 violation.

**Verdict enum (Gap #48, codified 2026-05-26)**: \`PASTE-READY\` /
\`HELD-PENDING-EVIDENCE\` / \`NEGATIVE-CLOSED\` /
\`NEGATIVE-CLOSED-WITH-OBSERVATION-FOR-EXISTING-BUNDLE\` (incremental
fold-in candidate for an already-staged bundle; lane MAY NOT auto-stage
per L34 v2; include an \`observation:\` block per
\`docs/HACKER_LANE_BRIEF_TEMPLATE.md\` Section 6) / \`OOS\`. Legacy
\`PASS\`/\`NEGATIVE\`/\`BLOCKED\`/\`cooldown-refusal\` remain for
tool-build / capability / infrastructure lanes.
EOF
}

# Compose the prompt per lane-type.
{
  emit_header
  emit_layer1_foundation
  case "$LANE_TYPE" in
    hunt|drill|comp|fuzz)
      emit_layer1_hacker_stack
      ;;
    filing)
      emit_layer1_filing_stack
      ;;
    tool-build)
      # Tool-build lanes only need the foundation. No hacker stack, no
      # filing stack. Keep the prompt minimal.
      ;;
  esac
  emit_layer1_close
  emit_pathspec_section
  emit_goal_scope_section
  emit_method_section
  emit_discipline_section
  emit_reply_section
} > "$TMPOUT"

if [ -n "$OUTPUT" ]; then
  cp "$TMPOUT" "$OUTPUT"
  if [ "$QUIET" -eq 0 ]; then
    echo "[lane-brief-template] wrote: $OUTPUT ($(wc -l < "$OUTPUT") lines)"
  fi
else
  cat "$TMPOUT"
fi
