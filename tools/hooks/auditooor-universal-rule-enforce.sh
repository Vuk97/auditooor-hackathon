#!/usr/bin/env bash
# auditooor-universal-rule-enforce.sh
#
# UNIVERSAL PreToolUse enforcement hook. Blocks ANY agent action that
# requires a rule/tool/MCP-callable citation when the surrounding
# context (prompt body, recent log entries, env vars, file content)
# does not show that citation AND no rebuttal-marker exception is
# present.
#
# Operator directive 2026-05-26:
# "everything needs to map to a mcp callable or the ruleset or the
#  tool (with ability to choose exception) otherwise agent actions
#  in claude desktop and codex are blocked (with a block reason)".
#
# Composition with existing PreToolUse hooks
# ------------------------------------------
# This hook ADDS enforcement; it does not replace any existing hook.
# All Agent dispatches still pass through auditooor-mcp-first-enforce.sh
# (MCP-first + spawn-worker routing). All Bash git commits still pass
# through auditooor-pre-commit-mcp-check.sh. The universal hook covers
# the GAP between those: per-tool action-class checks driven by
# tools/hooks/auditooor-universal-action-classifier.py.
#
# Decision contract
# -----------------
# Stdin: PreToolUse JSON from Anthropic harness.
# Stdout: either nothing (allow) or a hookSpecificOutput JSON with
#         permissionDecision=deny + permissionDecisionReason.
# Exit code: always 0 (per Anthropic hook contract; deny is via JSON).
#
# Fail-open posture
# -----------------
# Any internal error (missing classifier, jq unavailable, classifier
# parse error) -> allow. The hook MUST NOT break unrelated dev work.
# Errors are logged to .auditooor/universal_action_enforcement_log.jsonl
# for forensic review.

set -uo pipefail

REPO_ROOT="$(git -C /Users/wolf/auditooor-mcp rev-parse --show-toplevel 2>/dev/null || echo /Users/wolf/auditooor-mcp)"
CLASSIFIER="${REPO_ROOT}/tools/hooks/auditooor-universal-action-classifier.py"
DEFAULT_LOG="${REPO_ROOT}/.auditooor/universal_action_enforcement_log.jsonl"
LOG_PATH="${AUDITOOOR_UNIVERSAL_LOG_PATH:-$DEFAULT_LOG}"
BYPASS_ENV_NAME="AUDITOOOR_UNIVERSAL_BYPASS"

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

ts_now() {
  python3 -c 'from datetime import datetime,timezone; print(datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%fZ"))' 2>/dev/null \
    || date -u +"%Y-%m-%dT%H:%M:%SZ"
}

log_event() {
  # log_event <event> <action_signature> <decision> <reason>
  local event="$1" sig="$2" decision="$3" reason="$4"
  local ts
  ts="$(ts_now)"
  mkdir -p "$(dirname "$LOG_PATH")" 2>/dev/null || true
  python3 - "$ts" "$event" "$sig" "$decision" "$reason" "$LOG_PATH" <<'PYEOF' 2>/dev/null || true
import json, sys, pathlib
ts, event, sig, decision, reason, log_path = sys.argv[1:7]
row = {"ts": ts, "event": event, "action_signature": sig, "decision": decision, "reason": reason, "hook": "auditooor-universal-rule-enforce.sh"}
pathlib.Path(log_path).parent.mkdir(parents=True, exist_ok=True)
with open(log_path, "a", encoding="utf-8") as fh:
    fh.write(json.dumps(row) + "\n")
PYEOF
}

emit_deny() {
  # emit_deny <reason>
  local reason="$1"
  python3 - "$reason" <<'PYEOF'
import json, sys
reason = sys.argv[1]
print(json.dumps({
  "hookSpecificOutput": {
    "hookEventName": "PreToolUse",
    "permissionDecision": "deny",
    "permissionDecisionReason": reason,
  }
}))
PYEOF
}

# ---------------------------------------------------------------------------
# Bypass check (operator escape hatch)
# Gap #54 (codified 2026-05-26): explicit env-propagation audit. When the
# bypass env var IS set, emit a JSONL row to .auditooor/universal_hook_audit.jsonl
# in addition to the existing universal_action_enforcement_log.jsonl
# emission. When the action body REFERENCES the bypass name but the env
# is NOT exported to the hook subprocess, emit a diagnostic row
# (bypass-name-referenced-but-not-set) so the propagation failure is
# observable in the audit log. SESSION-GAP-HUNT (2026-05-26) found 61
# bypass-env STRING references in transcripts with 0 bypass-env LOG
# entries, indicating the env var was never propagated to the hook.
# ---------------------------------------------------------------------------

input="$(cat)"

GAP54_AUDIT_LOG="${REPO_ROOT}/.auditooor/universal_hook_audit.jsonl"

gap54_log_jsonl() {
  # gap54_log_jsonl <event_kind> <bypass_set:bool> <reason>
  local event_kind="$1" bypass_set="$2" reason="$3"
  local ts
  ts="$(ts_now)"
  mkdir -p "$(dirname "$GAP54_AUDIT_LOG")" 2>/dev/null || true
  python3 - "$ts" "$event_kind" "$bypass_set" "$reason" "$GAP54_AUDIT_LOG" "$BYPASS_ENV_NAME" <<'PYEOF' 2>/dev/null || true
import json, os, pathlib, sys
ts, event_kind, bypass_set, reason, log_path, env_name = sys.argv[1:7]
row = {
  "ts": ts,
  "event": event_kind,
  "bypass": bypass_set == "true",
  "bypass_env_name": env_name,
  "bypass_env_value_present": bool(os.environ.get(env_name, "")),
  "reason": reason,
  "hook": "auditooor-universal-rule-enforce.sh",
  "schema": "auditooor.gap54_universal_hook_audit.v1",
}
pathlib.Path(log_path).parent.mkdir(parents=True, exist_ok=True)
with open(log_path, "a", encoding="utf-8") as fh:
    fh.write(json.dumps(row) + "\n")
PYEOF
}

# Bypass via env. Audit-logged for forensic review.
if [ "${!BYPASS_ENV_NAME:-}" = "1" ]; then
  log_event "bypass-env" "<unread>" "allow" "${BYPASS_ENV_NAME}=1"
  gap54_log_jsonl "bypass-env" "true" "operator-env-set"
  exit 0
fi

# Gap #54: when the action body references the bypass env name but the
# env is NOT set to "1", emit a propagation-failure diagnostic row. This
# is the inverse of the bypass-env event; it surfaces the case where
# operator MEANT to bypass but the env var didn't reach the hook.
if printf '%s' "$input" | grep -F -q "$BYPASS_ENV_NAME"; then
  gap54_log_jsonl "bypass-name-referenced-but-not-set" "false" \
    "$BYPASS_ENV_NAME referenced in action context but not exported to hook subprocess"
fi

# Classifier missing -> fail-open allow (audit-logged).
if [ ! -x "$CLASSIFIER" ] && [ ! -f "$CLASSIFIER" ]; then
  log_event "classifier-missing" "<unread>" "allow" "$CLASSIFIER not found"
  exit 0
fi

# ---------------------------------------------------------------------------
# Run classifier
# ---------------------------------------------------------------------------

classification="$(printf '%s' "$input" | python3 "$CLASSIFIER" 2>/dev/null)"
if [ -z "$classification" ]; then
  log_event "classifier-empty-output" "<unread>" "allow" "classifier produced no output"
  exit 0
fi

# Use python to parse classification + decide. Pure-bash JSON is brittle.
decision="$(python3 - "$classification" "$input" "$BYPASS_ENV_NAME" <<'PYEOF'
import json
import os
import re
import subprocess
import sys

classification = json.loads(sys.argv[1] or "{}")
payload = json.loads(sys.argv[2] or "{}")
bypass_env_name = sys.argv[3]

required = classification.get("required_rule_citations") or []
exception_required = bool(classification.get("exception_marker_required", False))
sig = classification.get("action_signature") or "<unread>"
remediation = classification.get("remediation") or ""

# If the classifier identified no required citations, allow.
if not required:
    print(json.dumps({"decision": "allow", "sig": sig, "reason": "no-citation-required"}))
    sys.exit(0)

tool_name = payload.get("tool_name") or ""
tool_input = payload.get("tool_input") or {}

# Compose the "context blob" we search for citations + rebuttal markers in.
# Order: prompt body (Agent), command body (Bash), file_path + new content
# (Edit/Write/MultiEdit), env vars relevant to bypass.
blob_parts: list[str] = []
if isinstance(tool_input, dict):
    for key in ("prompt", "command", "file_path", "new_string", "content", "old_string"):
        val = tool_input.get(key)
        if isinstance(val, str):
            blob_parts.append(val)
    edits = tool_input.get("edits")
    if isinstance(edits, list):
        for e in edits:
            if isinstance(e, dict):
                for k in ("old_string", "new_string"):
                    v = e.get(k)
                    if isinstance(v, str):
                        blob_parts.append(v)

# Env-var fall-through for blanket per-action operator overrides.
env_overrides = {
    "L34": os.environ.get("AUDITOOOR_L34_OPERATOR_AUTH", ""),
    "R36": os.environ.get("AUDITOOOR_R36_PATHSPEC_AUTH", ""),
    "R55": os.environ.get("R55_REBUTTAL", ""),
    "R14": os.environ.get("AUDITOOOR_R14_REBUTTAL", ""),
    "context-pack-id": os.environ.get("AUDITOOOR_MCP_CONTEXT_PACK_ID", ""),
    "mcp-session-token": os.environ.get("AUDITOOOR_MCP_SESSION_TOKEN", ""),
    "hacker-mcp-suite": os.environ.get("AUDITOOOR_HACKER_MCP_REBUTTAL", ""),
    # Phase 1 Tier-A EXTREME gap overrides (operator-incident anchored).
    # Spec: reports/v3_iter_2026-05-26/lane_ENFORCEMENT_AUDIT/phase1_extension_recommendations.md
    "NEVER-SKIP-HOOKS": os.environ.get("AUDITOOOR_NEVER_SKIP_HOOKS_BYPASS", ""),
    "NEVER-FORCE-PUSH-MAIN": os.environ.get("AUDITOOOR_NEVER_FORCE_PUSH_BYPASS", ""),
    "NEVER-GIT-CONFIG-CHANGE": os.environ.get("AUDITOOOR_NEVER_GIT_CONFIG_BYPASS", ""),
    "NEVER-DELETE-GISTS": os.environ.get("AUDITOOOR_NEVER_DELETE_GISTS_BYPASS", ""),
    "NEVER-INCREMENTNONCE": os.environ.get("AUDITOOOR_NEVER_INCREMENTNONCE_BYPASS", ""),
    "R55-FOREGROUND": os.environ.get("AUDITOOOR_R55_RAW_RESET_BYPASS", "") or os.environ.get("R55_REBUTTAL", ""),
}

# Map rule-id -> shell-comment rebuttal token (Phase 1 Tier-A only).
# The classifier emits the rebuttal_id via context_signals; the hook
# scans the Bash command body for `# extreme-rebuttal-<id>: <reason>`.
extreme_gap_rebuttal_ids = {
    "NEVER-SKIP-HOOKS": "gap1-no-verify",
    "NEVER-FORCE-PUSH-MAIN": "gap2-force-push-main",
    "NEVER-GIT-CONFIG-CHANGE": "gap3-git-config-write",
    "NEVER-DELETE-GISTS": "gap4-gist-delete",
    "NEVER-INCREMENTNONCE": "gap5-incrementNonce",
    "R55-FOREGROUND": "gap6-git-reset-hard-raw",
}

# Recent log probe: spawn_worker_log.jsonl entries can satisfy rule cites
# for Agent dispatches routed through spawn-worker.sh.
spawn_log = os.path.join(os.environ.get("HOME", "/Users/wolf"), "auditooor-mcp", ".auditooor", "spawn_worker_log.jsonl")
recent_log_blob = ""
try:
    if os.path.isfile(spawn_log):
        with open(spawn_log, "r", encoding="utf-8") as fh:
            lines = fh.readlines()[-30:]
        recent_log_blob = "\n".join(lines)
except Exception:
    pass

context_blob = "\n".join(blob_parts) + "\n" + recent_log_blob

missing: list[str] = []
satisfied: list[str] = []

for rule in required:
    rule_lower = rule.lower()
    # Match rebuttal markers in a few forms:
    # - <!-- r14-rebuttal: ... -->
    # - r14-rebuttal: ...
    # - L34-rebuttal: ...
    # - context_pack_id: <value> / context_pack_hash: <value>
    # - mcp-session-token sentinel
    rebuttal_patterns = [
        rf"<!--\s*{re.escape(rule_lower)}-rebuttal:\s*.{{1,200}}-->",
        rf"\b{re.escape(rule_lower)}-rebuttal:\s*.{{1,200}}",
    ]
    if rule == "context-pack-id":
        rebuttal_patterns += [
            r"context_pack_id\s*[:=]\s*['\"]?[A-Za-z0-9._:-]+",
            r"context_pack_hash\s*[:=]\s*['\"]?[A-Fa-f0-9]+",
        ]
    if rule == "mcp-session-token":
        rebuttal_patterns += [
            r"AUDITOOOR_MCP_SESSION_TOKEN",
            r"mcp[_-]session[_-]token",
        ]
    if rule == "hacker-mcp-suite":
        rebuttal_patterns += [
            r"vault_hacker_brief_for_lane",
            r"vault_hackerman_novel_vector_context",
            r"vault_chained_attack_plan_context",
            r"<!--\s*hacker-mcp-rebuttal:\s*.{1,200}-->",
        ]
    if rule == "R14":
        rebuttal_patterns += [
            r"tools/triager-amend-asymmetry\.py",
            r"triager_amend_asymmetry",
        ]
    if rule == "R36":
        rebuttal_patterns += [
            r"tools/agent-pathspec-register\.py",
            r"agent_pathspec\.json",
        ]
    if rule == "L34":
        rebuttal_patterns += [
            r"tools/l34-path-classifier\.py",
        ]

    # Phase 1 Tier-A EXTREME gaps: accept embedded shell-comment
    # rebuttal '# extreme-rebuttal-<gap-id>: <reason>' (<=200 chars).
    extreme_id = extreme_gap_rebuttal_ids.get(rule, "")
    if extreme_id:
        rebuttal_patterns += [
            rf"#\s*extreme-rebuttal-{re.escape(extreme_id)}\s*:\s*.{{1,200}}",
        ]

    found = False
    for pat in rebuttal_patterns:
        if re.search(pat, context_blob, re.IGNORECASE | re.DOTALL):
            found = True
            break
    if not found:
        env_val = env_overrides.get(rule, "")
        if env_val and env_val.strip():
            found = True
    if found:
        satisfied.append(rule)
    else:
        missing.append(rule)

if missing:
    reason = (
        f"auditooor-universal-rule-enforce: action_signature={sig} requires "
        f"rule citation for {missing}. " + (remediation or "")
        + f" To override, set ${bypass_env_name}=1 (audit-logged) or add the "
          f"appropriate rebuttal marker to the action context."
    )
    print(json.dumps({"decision": "deny", "sig": sig, "reason": reason, "missing": missing}))
    sys.exit(0)

print(json.dumps({"decision": "allow", "sig": sig, "reason": "citations-satisfied", "satisfied": satisfied}))
sys.exit(0)
PYEOF
)"

# Parse the python decision.
result_decision="$(printf '%s' "$decision" | python3 -c 'import json,sys; print(json.loads(sys.stdin.read()).get("decision",""))' 2>/dev/null)"
result_sig="$(printf '%s' "$decision" | python3 -c 'import json,sys; print(json.loads(sys.stdin.read()).get("sig",""))' 2>/dev/null)"
result_reason="$(printf '%s' "$decision" | python3 -c 'import json,sys; print(json.loads(sys.stdin.read()).get("reason",""))' 2>/dev/null)"

if [ "$result_decision" = "deny" ]; then
  log_event "deny" "$result_sig" "deny" "$result_reason"
  emit_deny "$result_reason"
  exit 0
fi

log_event "allow" "$result_sig" "allow" "$result_reason"
exit 0
