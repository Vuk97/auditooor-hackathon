#!/usr/bin/env bash
# lane-verdict-bus-autoappend.sh - PostToolUse hook for Agent/Task replies.
#
# Parses completed Agent/Task replies for a VERDICT: line and forwards one
# append request to tools/lane-verdict-bus.py. The bus tool owns atomic writes
# and idempotency by lane_id, candidate_id, and metadata.verdict_hash.
#
# Fail-open posture: this hook is advisory and must not block tool flow.

set -uo pipefail

if [[ "${AUDITOOOR_LANE_VERDICT_BUS_HOOK_DISABLE:-0}" == "1" ]]; then
  exit 0
fi

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/../.." && pwd)"
BUS_TOOL="${AUDITOOOR_LANE_VERDICT_BUS_TOOL:-${REPO_ROOT}/tools/lane-verdict-bus.py}"

payload="$(cat 2>/dev/null || true)"
if [[ -z "${payload}" ]]; then
  exit 0
fi

tmp_payload="$(mktemp 2>/dev/null || printf '/tmp/lane_verdict_bus_payload_%s.json' "$$")"
printf '%s' "${payload}" >"${tmp_payload}" 2>/dev/null || exit 0

BUS_TOOL="${BUS_TOOL}" REPO_ROOT="${REPO_ROOT}" python3 - "${tmp_payload}" <<'PY' || true
import hashlib
import json
import os
import re
import subprocess
import sys
from pathlib import Path


def advisory(reason: str) -> None:
    sys.stderr.write(f"[lane-verdict-bus-autoappend] {reason}\n")


def first_text(*values: object) -> str:
    for value in values:
        if isinstance(value, str) and value.strip():
            return value.strip()
    return ""


def response_text(value: object) -> str:
    if isinstance(value, str):
        return value
    if isinstance(value, dict):
        direct = first_text(value.get("output"), value.get("text"))
        if direct:
            return direct
        content = value.get("content")
        if isinstance(content, list):
            parts: list[str] = []
            for item in content:
                if isinstance(item, str):
                    parts.append(item)
                elif isinstance(item, dict) and isinstance(item.get("text"), str):
                    parts.append(item["text"])
            return "\n".join(parts)
    if isinstance(value, list):
        return "\n".join(response_text(item) for item in value)
    return ""


def extract_verdict(text: str) -> str:
    verdict_re = re.compile(
        r"^\s*(?:#{1,6}\s*)?(?:[-*]\s*)?(?:\*\*)?VERDICT(?:\*\*)?\s*:\s*(.+?)\s*$",
        re.IGNORECASE | re.MULTILINE,
    )
    match = verdict_re.search(text or "")
    if not match:
        return ""
    verdict = match.group(1).strip()
    verdict = re.sub(r"\s*\*\*\s*$", "", verdict).strip()
    return verdict[:500]


def extract_lane_id(prompt: str, reply: str, tool_input: dict) -> str:
    env_lane = os.environ.get("AUDITOOOR_LANE_ID", "")
    direct = first_text(env_lane, tool_input.get("lane_id"), tool_input.get("lane"))
    if direct:
        return safe_id(direct)
    haystack = "\n".join([prompt, reply])
    patterns = [
        r"\blane[_ -]?id\s*[:=]\s*`?([A-Za-z0-9_.-]{2,120})",
        r"\bLane\s*[:=]\s*`?([A-Za-z0-9_.-]{2,120})",
        r"\bWorker\s+([A-Za-z0-9_.-]{2,120})",
        r"\bYou are Worker\s+([A-Za-z0-9_.-]{2,120})",
    ]
    for pattern in patterns:
        match = re.search(pattern, haystack, re.IGNORECASE)
        if match:
            return safe_id(match.group(1))
    digest = hashlib.sha256(haystack.encode("utf-8", "replace")).hexdigest()[:12]
    return f"unknown-lane-{digest}"


def extract_candidate_id(prompt: str, reply: str, tool_input: dict, lane_id: str) -> str:
    direct = first_text(
        os.environ.get("AUDITOOOR_CANDIDATE_ID", ""),
        tool_input.get("candidate_id"),
        tool_input.get("candidate"),
    )
    if direct:
        return safe_id(direct)
    haystack = "\n".join([prompt, reply])
    patterns = [
        r"\bcandidate[_ -]?id\s*[:=]\s*`?([A-Za-z0-9_.:/-]{2,160})",
        r"\bcandidate\s*[:=]\s*`?([A-Za-z0-9_.:/-]{2,160})",
        r"\blead[_ -]?id\s*[:=]\s*`?([A-Za-z0-9_.:/-]{2,160})",
    ]
    for pattern in patterns:
        match = re.search(pattern, haystack, re.IGNORECASE)
        if match:
            return safe_id(match.group(1))
    return lane_id


def safe_id(value: str) -> str:
    cleaned = re.sub(r"[^A-Za-z0-9_.:-]+", "-", str(value).strip()).strip("-")
    return cleaned[:160] or "unknown"


def extract_model(prompt: str, reply: str, tool_input: dict) -> str:
    """Best-effort model label for calibration weighting (P12 join key).

    Advisory + fail-open: if we cannot confidently infer the model, return "" so
    the caller OMITS the metadata (the record stays cold-start / unweighted)
    rather than emitting a wrong join key. Never raises.
    """
    direct = first_text(
        os.environ.get("AUDITOOOR_LANE_MODEL", ""),
        os.environ.get("ANTHROPIC_MODEL", ""),
        tool_input.get("model"),
    )
    if direct:
        return safe_meta(direct)
    # A subagent dispatch commonly names the model in tool_input; some fan-out
    # dispatchers set model in {sonnet,haiku,opus}. Map those to the canonical
    # calibration provider label so the join lands. Unknown -> omit.
    haystack = "\n".join([prompt, reply])
    match = re.search(r"\bmodel\s*[:=]\s*`?([A-Za-z0-9_.:/-]{2,80})", haystack, re.IGNORECASE)
    if match:
        return safe_meta(match.group(1))
    return ""


def extract_task_type(prompt: str, reply: str, tool_input: dict) -> str:
    """Best-effort task_type label for calibration weighting (P12 join key).

    Advisory + fail-open: return "" to OMIT rather than guess wrong. The
    calibration allowlist is authoritative downstream; emitting a value not in
    the allowlist just degrades that record to cold-start (never crashes).
    """
    direct = first_text(
        os.environ.get("AUDITOOOR_LANE_TASK_TYPE", ""),
        tool_input.get("task_type"),
    )
    if direct:
        return safe_meta(direct)
    haystack = "\n".join([prompt, reply])
    match = re.search(
        r"\btask[_ -]?type\s*[:=]\s*`?([A-Za-z0-9_.:/-]{2,60})",
        haystack,
        re.IGNORECASE,
    )
    if match:
        return safe_meta(match.group(1))
    return ""


def safe_meta(value: str) -> str:
    cleaned = re.sub(r"[^A-Za-z0-9_.:/-]+", "-", str(value).strip()).strip("-")
    return cleaned[:80]


def extract_workspace(prompt: str, reply: str, tool_input: dict) -> str:
    direct = first_text(
        os.environ.get("AUDITOOOR_WS", ""),
        os.environ.get("CLAUDE_PROJECT_DIR", ""),
        tool_input.get("workspace_path"),
        tool_input.get("workspace"),
        tool_input.get("cwd"),
    )
    if direct:
        return str(Path(direct).expanduser().resolve())
    haystack = "\n".join([prompt, reply])
    match = re.search(
        r"(/Users/wolf/(?:audits/[A-Za-z0-9_.-]+|auditooor-mcp|Downloads/auditooor|auditooor-worktrees/[A-Za-z0-9_.-]+))",
        haystack,
    )
    if match:
        return str(Path(match.group(1)).expanduser().resolve())
    return str(Path.cwd().resolve())


payload_path = Path(sys.argv[1])
try:
    payload = json.loads(payload_path.read_text(encoding="utf-8"))
except Exception:
    sys.exit(0)

if not isinstance(payload, dict):
    sys.exit(0)

tool_name = str(payload.get("tool_name") or "")
if tool_name not in {"Agent", "Task"}:
    sys.exit(0)

tool_input = payload.get("tool_input") or payload.get("input") or {}
if not isinstance(tool_input, dict):
    tool_input = {}

prompt = first_text(tool_input.get("prompt"), tool_input.get("description"))
reply = response_text(payload.get("tool_response"))
verdict = extract_verdict(reply)
if not verdict:
    advisory("lane-verdict-bus-missing-verdict tool=%s" % (tool_name or "-"))
    sys.exit(0)

bus_tool = Path(os.environ.get("BUS_TOOL", "")).expanduser()
if not bus_tool.is_file():
    advisory(f"lane-verdict-bus-tool-missing path={bus_tool}")
    sys.exit(0)

workspace = extract_workspace(prompt, reply, tool_input)
lane_id = extract_lane_id(prompt, reply, tool_input)
candidate_id = extract_candidate_id(prompt, reply, tool_input, lane_id)
verdict_hash = hashlib.sha256(verdict.encode("utf-8", "replace")).hexdigest()
reply_hash = hashlib.sha256(reply.encode("utf-8", "replace")).hexdigest()

cmd = [
    sys.executable,
    str(bus_tool),
    "append",
    "--workspace",
    workspace,
    "--lane-id",
    lane_id,
    "--candidate-id",
    candidate_id,
    "--verdict",
    verdict,
    "--metadata",
    f"verdict_hash={verdict_hash}",
    "--metadata",
    f"source=posttooluse:{tool_name}",
    "--metadata",
    f"reply_sha256={reply_hash}",
]

# P12: advisory track-record weighting join keys. Emitted ADDITIVELY as
# free-form metadata (already permitted by the bus schema). Omitted entirely
# when they cannot be confidently inferred, so those records stay cold-start
# (unweighted) rather than carrying a wrong join key. Never blocks the append.
model = extract_model(prompt, reply, tool_input)
if model:
    cmd += ["--metadata", f"model={model}"]
task_type = extract_task_type(prompt, reply, tool_input)
if task_type:
    cmd += ["--metadata", f"task_type={task_type}"]

try:
    proc = subprocess.run(cmd, capture_output=True, text=True, check=False)
except Exception as exc:
    advisory(f"lane-verdict-bus-append-error error={exc}")
    sys.exit(0)

if proc.returncode != 0:
    err = (proc.stderr or proc.stdout or "").strip().replace("\n", " ")[:500]
    advisory(f"lane-verdict-bus-append-failed rc={proc.returncode} detail={err}")
    sys.exit(0)

detail = (proc.stdout or "").strip().replace("\n", " ")[:300]
if detail:
    advisory(f"lane-verdict-bus-appended lane_id={lane_id} candidate_id={candidate_id} {detail}")
else:
    advisory(f"lane-verdict-bus-appended lane_id={lane_id} candidate_id={candidate_id}")
PY

rm -f "${tmp_payload}" 2>/dev/null || true
exit 0
