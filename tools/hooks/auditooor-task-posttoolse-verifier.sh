#!/usr/bin/env bash
# auditooor-task-posttoolse-verifier.sh
#
# PostToolUse hook (matcher: Task). Fires automatically when any Task subagent
# completes. Runs the MCP-citation behavioral verifier inline against the
# subagent's report output (`tool_response`) and logs the verdict to
# `<workspace>/.auditooor/task_verifier_log.jsonl`.
#
# Non-blocking: PostToolUse exit codes are advisory. We always exit 0 even on
# FAIL; the verdict line is emitted to stderr (Claude Code surfaces stderr as
# system-context for the next turn) so the orchestrator sees the warning.
#
# Pairs with the manual-invoke verifier
#   `~/.claude/hooks/auditooor-task-report-mcp-verifier.sh`
# (same Rule 1/2/3 logic; auto-fires per Task instead of needing a report file).
#
# Receives full PostToolUse JSON on stdin:
#   { "tool_name": "Task",
#     "tool_input": { "subagent_type": "...", "prompt": "...", ... },
#     "tool_response": "<final report markdown>" or { "content": [...] } }
#
# Kill-switch: AUDITOOOR_TASK_POSTHOOK_VERIFIER_DISABLE=1 -> exit 0 silently.

set -u

# -- 1. Kill-switch -----------------------------------------------------------
if [ "${AUDITOOOR_TASK_POSTHOOK_VERIFIER_DISABLE:-0}" = "1" ]; then
  exit 0
fi

# -- 2. Read stdin ------------------------------------------------------------
PAYLOAD="$(cat 2>/dev/null || true)"
if [ -z "${PAYLOAD}" ]; then
  exit 0
fi

# -- 3. Payload-aware audits-class guard -------------------------------------
# shellcheck source=/Users/wolf/.claude/hooks/_auditooor_payload_guard.sh
. /Users/wolf/.claude/hooks/_auditooor_payload_guard.sh
_auditooor_payload_guard "${PAYLOAD}" || exit 0

# -- 4. Resolve workspace for log dir ----------------------------------------
PWD_NOW="$(pwd 2>/dev/null || true)"
_AUDITS_FROM_PAYLOAD=""
case "${PWD_NOW}" in
  *auditooor*|*Vuk97*|*/audits/spark*|*/audits/*) ;;
  *)
    _AUDITS_FROM_PAYLOAD="$(printf '%s' "${PAYLOAD}" \
      | grep -oE '/Users/wolf/audits/[a-zA-Z0-9_-]+' \
      | head -1)"
    ;;
esac

if [ -n "${_AUDITS_FROM_PAYLOAD}" ]; then
  LOG_DIR="${_AUDITS_FROM_PAYLOAD}/.auditooor"
else
  LOG_DIR="${PWD_NOW}/.auditooor"
fi
mkdir -p "${LOG_DIR}" 2>/dev/null || exit 0

# -- 5. Run inline verifier via python ---------------------------------------
PYHELPER="$(mktemp)"
cat > "${PYHELPER}" <<'PYEOF'
import json, os, re, sys, time, hashlib

try:
    p = json.load(sys.stdin)
except Exception:
    sys.exit(0)
if not isinstance(p, dict):
    sys.exit(0)

if (p.get("tool_name") or "") != "Task":
    sys.exit(0)

tool_input = p.get("tool_input") or p.get("input") or {}
if not isinstance(tool_input, dict):
    tool_input = {}
subagent_type = tool_input.get("subagent_type") or ""
prompt = tool_input.get("prompt") or tool_input.get("description") or ""
if not isinstance(prompt, str):
    prompt = ""

# tool_response shapes observed:
#   - bare string (report markdown)
#   - {"content": [{"type": "text", "text": "..."}, ...]}
#   - {"output": "..."} (some adapters)
tool_response = p.get("tool_response")
report_text = ""
if isinstance(tool_response, str):
    report_text = tool_response
elif isinstance(tool_response, dict):
    if isinstance(tool_response.get("output"), str):
        report_text = tool_response["output"]
    elif isinstance(tool_response.get("text"), str):
        report_text = tool_response["text"]
    else:
        content = tool_response.get("content")
        if isinstance(content, list):
            parts = []
            for item in content:
                if isinstance(item, dict) and isinstance(item.get("text"), str):
                    parts.append(item["text"])
                elif isinstance(item, str):
                    parts.append(item)
            report_text = "\n".join(parts)

session_id = p.get("session_id") or ""
session_id_trunc = session_id[:8] if isinstance(session_id, str) else ""
ts = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
log_dir = os.environ.get("AUDIT_LOG_DIR", ".auditooor")

# --- Verifier logic (mirrors auditooor-task-report-mcp-verifier.sh) ---------
def verify(body):
    """Returns (verdict, reason). verdict in {PASS, FAIL, SKIP}."""
    if not body or not body.strip():
        return ("SKIP", "empty-report-output")

    # Rule 1: pack-id citation
    pat_packid = re.compile(
        r'auditooor\.(?:vault_|hackerman\.)[a-z_]+\.v1'
        r'|context_pack_id\s*[:=]\s*[`"]?auditooor'
    )
    if not pat_packid.search(body):
        return ("FAIL", "missing-MCP-callable-pack-id-citation")

    # Rule 2: pack hash (40-64 hex)
    if not re.search(r'[0-9a-f]{40,64}', body):
        return ("FAIL", "missing-context_pack_hash-citation")

    # Rule 3: if hunt-lane shape (verdict keyword present), require MCP callable
    has_verdict_shape = bool(re.search(
        r'verdict|NEGATIVE|FILEABLE|HOLD|DROP', body))
    if has_verdict_shape:
        callable_pat = re.compile(
            r'vault_attack_class_evidence|vault_originality_context'
            r'|vault_dupe_rejection_context|vault_hacker_brief_for_lane'
            r'|vault_function_mindset|vault_kill_rubric_context'
            r'|vault_triager_pattern_context|vault_resume_context'
            r'|vault_external_corpus_search|vault_chained_attack_plan_context'
            r'|vault_knowledge_gap_context'
        )
        if not callable_pat.search(body):
            # Alt: MCP section header + >=1 schema citation
            if re.search(
                r'MCP[- ]?first|MCP recall|MCP context[- ]?pack|MCP receipt|/tmp/lane_',
                body
            ):
                schema_hits = len(re.findall(
                    r'auditooor\.(?:vault_|hackerman\.)[a-z_]+\.v1', body))
                if schema_hits < 1:
                    return ("FAIL",
                            "hunt-lane-shape-but-MCP-header-without-schema-cite")
            else:
                return ("FAIL",
                        "hunt-lane-shape-but-no-MCP-callable-or-recall-section")
    return ("PASS", "ok")


verdict, reason = verify(report_text)

# Lane-id heuristic from prompt (helps cross-referencing)
lane_id = ""
m = re.search(
    r'lane[_\s-]?id["\s:]+([A-Z][A-Z0-9_-]{2,80})',
    prompt, re.IGNORECASE
)
if m:
    lane_id = m.group(1)

report_len = len(report_text)
report_sha = hashlib.sha256(report_text.encode("utf-8", "replace")).hexdigest()[:16] if report_text else ""

row = {
    "ts": ts,
    "tool": "Task",
    "subagent_type": subagent_type,
    "lane_id": lane_id,
    "verdict": verdict,
    "reason": reason,
    "report_chars": report_len,
    "report_sha256_16": report_sha,
    "agent_session_id_truncated": session_id_trunc,
}

try:
    with open(os.path.join(log_dir, "task_verifier_log.jsonl"),
              "a", encoding="utf-8") as fh:
        fh.write(json.dumps(row, sort_keys=True) + "\n")
except Exception:
    pass

# Emit warning to stderr on FAIL (Claude Code surfaces stderr to next turn).
if verdict == "FAIL":
    sys.stderr.write(
        "[auditooor-task-posttoolse-verifier] FAIL "
        f"subagent={subagent_type or '-'} lane={lane_id or '-'} "
        f"reason={reason} "
        f"(non-blocking; see {log_dir}/task_verifier_log.jsonl)\n"
    )

sys.exit(0)
PYEOF

# Discard stdout (we have nothing to say there), preserve stderr so the
# FAIL warning surfaces to Claude Code's next-turn system-context.
AUDIT_LOG_DIR="${LOG_DIR}" printf '%s' "${PAYLOAD}" \
  | AUDIT_LOG_DIR="${LOG_DIR}" python3 "${PYHELPER}" >/dev/null || true
rm -f "${PYHELPER}" 2>/dev/null || true

exit 0
