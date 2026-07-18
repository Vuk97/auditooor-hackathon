#!/usr/bin/env bash
# mcp-native-usage-enforce.sh - PreToolUse hook: warn when agents shell out
# to vault-mcp-server.py --call <name> instead of using the native
# mcp__auditooor-vault__<name> tool.
#
# Registered as PreToolUse hook (matcher: Bash) in ~/.claude/settings.json.
# Also sourced by tools/auditooor-codex-wrapper.sh for Codex-side parity.
#
# WHY: tools/vault-mcp-server.py is registered as a stdio MCP server in
# ~/.claude.json (mcpServers.auditooor-vault) and ~/.codex/config.toml
# ([mcp_servers.auditooor]). The native tools surface as
# mcp__auditooor-vault__vault_*. When agents shell out via
#   python3 tools/vault-mcp-server.py --call vault_resume_context ...
# they run the CURRENT disk code, but the native tool runs the REGISTERED
# SNAPSHOT (the version of vault-mcp-server.py at the time Claude Desktop /
# Codex was last (re)started). These DIVERGE after any edit to vault-mcp-server.py.
# The shell-out habit defeats the point of MCP registration.
#
# MODES:
#   Default: WARN-only (exit 0) - emits message to stderr, does not block.
#   AUDITOOOR_MCP_NATIVE_STRICT=1: hard-block (exit 2) - refuses the Bash call.
#
# ESCAPE: add  <!-- mcp-native-rebuttal: <reason up to 200 chars> -->  anywhere
# in the command string to suppress the warning (e.g. when testing disk edits
# before restart, or a callable not yet in native registration).
#
# INPUT: Claude PreToolUse hooks receive the tool input via stdin as JSON.
# The hook reads stdin, extracts the Bash command string, and checks it.
# It also accepts the command as $1 for codex-wrapper direct invocation.
#
# CALLABLE MAP: the native tool names are  mcp__auditooor-vault__<callable>
# where <callable> is the vault_* function name from --help output.

set -euo pipefail

# ---------------------------------------------------------------------------
# Known native callables (as of 2026-05-28; matches vault-mcp-server.py --help)
# ---------------------------------------------------------------------------
KNOWN_CALLABLES=(
  vault_active_roadmap
  vault_adversarial_hypothesis_differential
  vault_agent_artifact_mining_context
  vault_agent_learning_context
  vault_anti_pattern_corpus
  vault_attack_class_evidence
  vault_attack_class_evidence_v2
  vault_attack_class_evidence_v3
  vault_attack_class_orphan_report
  vault_attack_class_taxonomy
  vault_audit_deep_manifest_summary
  vault_brain_prime_context
  vault_bug_class_priority
  vault_bug_family_heatmap
  vault_capability_inventory
  vault_causal_chain_lookup
  vault_chain_prefix_match
  vault_chained_attack_plan_context
  vault_codified_rules_digest
  vault_commit_mining_state
  vault_corpus_freshness
  vault_corpus_lineage
  vault_corpus_mining_state
  vault_corpus_search
  vault_corpus_subtree_summary
  vault_cosmos_evidence_pack_context
  vault_cross_language_pattern_lift
  vault_current_to_exploit_conversion_gate_context
  vault_defender_narrative_simulator
  vault_detector_action_graph_context
  vault_detector_backtest
  vault_detector_provenance
  vault_detector_provenance_v2
  vault_dispatch_brief_skeleton
  vault_dispatch_context
  vault_dupe_advisory_check
  vault_dupe_rejection_context
  vault_engage_report_context
  vault_engagement_status
  vault_exploit_chain_unifier
  vault_exploit_context
  vault_exploit_narratives_synthesized
  vault_exploit_queue_context
  vault_exploit_severity_scope_oracle
  vault_external_corpus_search
  vault_fanout_pattern_library
  vault_finalization_context
  vault_finalization_manifest_context
  vault_finding_lineage
  vault_fork_divergence_attack_surface
  vault_fp_precision_report
  vault_fp_runner_results
  vault_function_mindset
  vault_function_shape_attack_evidence
  vault_function_signature_shape
  vault_get
  vault_global_chain_template_match
  vault_goal_state
  vault_hacker_brief_for_lane
  vault_hacker_brief_for_lane_v2
  vault_hacker_brief_for_lane_v3
  vault_hacker_questions
  vault_hackerman_chain_candidates
  vault_hackerman_detector_relationships
  vault_hackerman_exploit_predicates
  vault_hackerman_go_cosmos_inventory
  vault_hackerman_novel_vector_context
  vault_harness_context
  vault_harness_failure_context
  vault_high_impact_execution_bridge_context
  vault_high_plus_submission_gate
  vault_intent_resolve
  vault_invariant_library
  vault_issue_session_token
  vault_kill_rubric_context
  vault_knowledge_gap_context
  vault_known_dead_ends
  vault_lane_cooldown_check
  vault_lane_skeleton_filler
  vault_lane_verdict_bus
  vault_language_patterns
  vault_live_target_report
  vault_llm_calibration
  vault_loop_finalization_check
  vault_mcp_explorer_context
  vault_mimo_corpus_intelligence
  vault_mining_health
  vault_next_loop
  vault_originality_before_proof_gate
  vault_originality_context
  vault_outcome_context
  vault_per_function_hunter_brief
  vault_poc_execution_record_context
  vault_poc_falsification_context
  vault_post_filing_outcome_replay_patterns
  vault_post_mortem_corpus
  vault_proof_artifact_index_context
  vault_provider_capacity
  vault_realworld_recall_gap_priorities
  vault_remember
  vault_resume_context
  vault_rollup_digest
  vault_route
  vault_search
  vault_semantic_match_verify
  vault_severity_calibration
  vault_solidity_changelog_drift_context
  vault_solidity_detector_proof_context
  vault_spark_engagement_context
  vault_tok_a_corpus
  vault_toolsite_context
  vault_triager_pattern_context
  vault_triager_precheck_rules
  vault_triager_simulate
  vault_verify_session_token
  vault_zk_template_lookup
)

# ---------------------------------------------------------------------------
# Extract command string
# ---------------------------------------------------------------------------
CMD=""
if [ -n "${1:-}" ]; then
  # Direct invocation from codex-wrapper (command string as $1)
  CMD="$1"
else
  # PreToolUse hook: read JSON from stdin, extract command field
  INPUT=$(cat 2>/dev/null || true)
  if [ -n "$INPUT" ]; then
    CMD=$(printf '%s' "$INPUT" | python3 -c "
import sys, json
try:
    d = json.load(sys.stdin)
    # Try tool_input.command (Claude Code hook format)
    cmd = d.get('tool_input', d).get('command', '')
    print(cmd)
except Exception:
    pass
" 2>/dev/null || true)
  fi
fi

# Nothing to check
if [ -z "$CMD" ]; then
  exit 0
fi

# ---------------------------------------------------------------------------
# Rebuttal escape: if the command string contains mcp-native-rebuttal, skip
# ---------------------------------------------------------------------------
if printf '%s' "$CMD" | grep -qE 'mcp-native-rebuttal:\s*\S'; then
  exit 0
fi

# ---------------------------------------------------------------------------
# Check for vault-mcp-server.py --call pattern
# ---------------------------------------------------------------------------
if ! printf '%s' "$CMD" | grep -qE 'vault-mcp-server\.py\s+--call\s+'; then
  exit 0
fi

# Extract the callable name
CALLABLE=$(printf '%s' "$CMD" | grep -oE -- '--call\s+vault_[a-z_0-9]+' | head -1 | awk '{print $2}')
if [ -z "$CALLABLE" ]; then
  exit 0
fi

# Check if this callable is in the known native list
IS_NATIVE=0
for c in "${KNOWN_CALLABLES[@]}"; do
  if [ "$c" = "$CALLABLE" ]; then
    IS_NATIVE=1
    break
  fi
done

if [ "$IS_NATIVE" -eq 0 ]; then
  # Callable not yet registered natively - this is a legitimate shell-out
  # (e.g. a newly-added callable not yet in Claude Desktop registration).
  # Just exit 0.
  exit 0
fi

NATIVE_TOOL="mcp__auditooor-vault__${CALLABLE}"

cat >&2 <<EOF
[mcp-native-enforce] WARNING: shell-out to vault-mcp-server.py detected.
  Command: python3 ... vault-mcp-server.py --call ${CALLABLE} ...
  Native tool: ${NATIVE_TOOL}

  The subprocess runs the CURRENT DISK CODE of vault-mcp-server.py.
  The native MCP tool runs the REGISTERED SNAPSHOT (the version loaded
  when Claude Desktop / Codex was last restarted).
  After any edit to vault-mcp-server.py these two DIVERGE - the native
  tool may return stale schema results or miss new callables.

  PREFERRED: use the native tool  ${NATIVE_TOOL}  via the MCP tool interface.

  RESTART-ON-EDIT discipline: after editing vault-mcp-server.py, restart
  Claude Desktop (Cmd+Q + reopen) or restart the Codex daemon to load the
  updated snapshot into the native registration.

  ESCAPE: add  <!-- mcp-native-rebuttal: <reason> -->  in the command to
  suppress this warning for legitimate cases (testing disk edits before
  restart, callable not yet in native registration, etc.).
EOF

STRICT="${AUDITOOOR_MCP_NATIVE_STRICT:-0}"
if [ "$STRICT" = "1" ]; then
  echo "[mcp-native-enforce] BLOCKED (AUDITOOOR_MCP_NATIVE_STRICT=1). Use native tool or add mcp-native-rebuttal escape." >&2
  exit 2
fi

# Default: warn-only
exit 0
