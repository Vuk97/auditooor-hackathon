#!/usr/bin/env bash
# auditooor-corpus-change-refresh.sh - LIFT-9 PostToolUse hook
#
# Auto-refresh downstream MCP callable inputs when a corpus file is touched.
#
# Triggered by PostToolUse for Edit / Write / MultiEdit / Bash when the file
# path (Edit/Write/MultiEdit) OR the bash command body (Bash) targets one of
# the corpus surfaces:
#   audit/corpus_tags/tags/**/*.{yaml,json,md}
#   audit/corpus_tags/derived/**/*.{jsonl,json}
#   obsidian-vault/anti-patterns/**/*.{md,yaml}
#   obsidian-vault/mining/**/*.md
#   reference/patterns.dsl*/**/*.yaml
#
# Bash detection (LIFT-24): inspects the command string for shell shapes
# that write / delete files under the corpus globs:
#   cp <src> audit/corpus_tags/...
#   mv <src> audit/corpus_tags/...
#   sed -i ... audit/corpus_tags/...
#   tee audit/corpus_tags/...
#   python3 ... > audit/corpus_tags/...
#   echo ... >> audit/corpus_tags/...
#   rm audit/corpus_tags/...   (deletion also triggers refresh)
# Read-only shapes (grep / cat / ls / find / wc / head / tail / awk) WITHOUT
# a write redirect are skipped.
#
# When triggered, runs the refresh commands in the background (non-blocking)
# and appends NDJSON status records to .auditooor/corpus_refresh_log.jsonl.
#
# Throttling: skips fresh refreshes within AUDITOOOR_CORPUS_REFRESH_THROTTLE_SECONDS
# (default 60s) of the previous successful trigger, tracked via the timestamp
# file .auditooor/corpus_refresh_last_run.ts
#
# Disable: export AUDITOOOR_CORPUS_REFRESH_HOOK_DISABLE=1
# Verbose: export AUDITOOOR_CORPUS_REFRESH_HOOK_VERBOSE=1 (logs skipped events)
# Synchronous (test-only): export AUDITOOOR_CORPUS_REFRESH_HOOK_SYNC=1
#
# Fail-open posture: any internal error -> exit 0 silently. The hook MUST
# never block a corpus write.

set -uo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/../.." && pwd)"
LOG_DIR="${REPO_ROOT}/.auditooor"
LOG_FILE="${LOG_DIR}/corpus_refresh_log.jsonl"
THROTTLE_FILE="${LOG_DIR}/corpus_refresh_last_run.ts"
THROTTLE_SECONDS="${AUDITOOOR_CORPUS_REFRESH_THROTTLE_SECONDS:-60}"

# Allow tests / callers to override the log + throttle file locations.
if [[ -n "${AUDITOOOR_CORPUS_REFRESH_LOG_FILE:-}" ]]; then
  LOG_FILE="${AUDITOOOR_CORPUS_REFRESH_LOG_FILE}"
fi
if [[ -n "${AUDITOOOR_CORPUS_REFRESH_THROTTLE_FILE:-}" ]]; then
  THROTTLE_FILE="${AUDITOOOR_CORPUS_REFRESH_THROTTLE_FILE}"
fi

mkdir -p "$(dirname "${LOG_FILE}")" 2>/dev/null || true
mkdir -p "$(dirname "${THROTTLE_FILE}")" 2>/dev/null || true

ts_now() {
  python3 -c 'from datetime import datetime,timezone; print(datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%fZ"))' 2>/dev/null \
    || date -u +"%Y-%m-%dT%H:%M:%SZ"
}

emit_log() {
  # emit_log <event> <reason> [trigger_path]
  local event="$1"
  local reason="$2"
  local trigger="${3:-}"
  local ts
  ts="$(ts_now)"
  python3 - "$event" "$reason" "$trigger" "$ts" "$LOG_FILE" <<'PY' 2>/dev/null || true
import json, sys, os
event, reason, trigger, ts, log_file = sys.argv[1:6]
rec = {
    "schema_version": "auditooor.corpus_refresh_log.v1",
    "ts_utc": ts,
    "event": event,
    "reason": reason,
}
if trigger:
    rec["trigger_path"] = trigger
os.makedirs(os.path.dirname(log_file), exist_ok=True)
with open(log_file, "a", encoding="utf-8") as fh:
    fh.write(json.dumps(rec, sort_keys=True) + "\n")
PY
}

# Disable kill-switch.
if [[ "${AUDITOOOR_CORPUS_REFRESH_HOOK_DISABLE:-0}" == "1" ]]; then
  [[ "${AUDITOOOR_CORPUS_REFRESH_HOOK_VERBOSE:-0}" == "1" ]] && emit_log "disabled" "AUDITOOOR_CORPUS_REFRESH_HOOK_DISABLE=1" ""
  exit 0
fi

# Read PostToolUse payload.
payload="$(cat 2>/dev/null || true)"
if [[ -z "${payload}" ]]; then
  exit 0
fi

# Extract tool_name + file_path.
tool_name="$(printf '%s' "${payload}" | python3 -c \
  "import sys,json
try:
    d=json.load(sys.stdin); print(d.get('tool_name',''))
except Exception:
    print('')" 2>/dev/null || true)"

file_path="$(printf '%s' "${payload}" | python3 -c \
  "import sys,json
try:
    d=json.load(sys.stdin); ti=d.get('tool_input',{}) or {}
    print(ti.get('file_path') or ti.get('path') or '')
except Exception:
    print('')" 2>/dev/null || true)"

bash_command="$(printf '%s' "${payload}" | python3 -c \
  "import sys,json
try:
    d=json.load(sys.stdin); ti=d.get('tool_input',{}) or {}
    print(ti.get('command') or '')
except Exception:
    print('')" 2>/dev/null || true)"

# Only fire for write-class tools.
case "${tool_name}" in
  Edit|Write|MultiEdit|Bash) ;;
  *) exit 0 ;;
esac

# Bash branch (LIFT-24): extract a write-target file path from the command
# string, or exit 0 if the command is read-only / does not touch corpus.
if [[ "${tool_name}" == "Bash" ]]; then
  if [[ -z "${bash_command}" ]]; then
    exit 0
  fi
  # Detect file-write intent against corpus globs by scanning the command.
  # We pass the command to a small python helper that returns the first
  # matching corpus path (empty string -> skip). Read-only commands return
  # empty.
  bash_target="$(BASH_CMD="${bash_command}" python3 -c '
import os, re, sys
cmd = os.environ.get("BASH_CMD", "")
if not cmd:
    sys.exit(0)
# Corpus path predicate.
CORPUS_RE = re.compile(
    r"(?:audit/corpus_tags/tags/[^\s\x27\x22&|;><]+|"
    r"audit/corpus_tags/derived/[^\s\x27\x22&|;><]+|"
    r"obsidian-vault/anti-patterns/[^\s\x27\x22&|;><]+|"
    r"obsidian-vault/mining/[^\s\x27\x22&|;><]+|"
    r"reference/patterns\.dsl[^\s\x27\x22&|;><]*/[^\s\x27\x22&|;><]+)"
)
# 1. Write-redirect form: `... > <corpus_path>` or `... >> <corpus_path>`.
redirect = re.search(r">>?\s*(\S+)", cmd)
if redirect:
    tgt = redirect.group(1).strip("\x27\x22")
    if CORPUS_RE.search(tgt):
        print(tgt)
        sys.exit(0)
# 1b. `| tee [-a] <corpus_path>` form.
tee = re.search(r"\|\s*tee\s+(?:-a\s+)?(\S+)", cmd)
if tee:
    tgt = tee.group(1).strip("\x27\x22")
    if CORPUS_RE.search(tgt):
        print(tgt)
        sys.exit(0)
# 2. Write-utility form: a write/mutate utility token appears in the
#    command AND a corpus path appears in the command. Read-only utilities
#    (grep, cat, ls, find, wc, head, tail, awk-reading, file, md5sum,
#    sha256sum) do not match WRITE_UTILS so commands like
#    `grep foo audit/corpus_tags/...` skip cleanly.
WRITE_UTILS = re.compile(
    r"(?<![A-Za-z0-9._-])(cp|mv|rm|sed\s+-i|tee|touch|install|ln|dd|"
    r"gzip|gunzip|bzip2|xz|zip|unzip|tar|rsync)(?![A-Za-z0-9._-])"
)
if WRITE_UTILS.search(cmd):
    m = CORPUS_RE.search(cmd)
    if m:
        print(m.group(0))
        sys.exit(0)
# 3. Heredoc / pipe writes (`cat <<EOF > corpus`, `python3 script > corpus`)
#    are caught by the redirect form above.
' 2>/dev/null || true)"
  if [[ -z "${bash_target}" ]]; then
    [[ "${AUDITOOOR_CORPUS_REFRESH_HOOK_VERBOSE:-0}" == "1" ]] && emit_log "skipped-non-corpus-bash" "bash command does not target corpus path" "${bash_command:0:200}"
    exit 0
  fi
  file_path="${bash_target}"
fi

if [[ -z "${file_path}" ]]; then
  exit 0
fi

# Normalize to absolute path against REPO_ROOT when relative.
if [[ "${file_path}" != /* ]]; then
  file_path="${REPO_ROOT}/${file_path}"
fi

# Path-based corpus detection. Match any of the configured prefixes / globs.
is_corpus_path() {
  local p="$1"
  case "$p" in
    */audit/corpus_tags/tags/*.yaml|\
    */audit/corpus_tags/tags/*.json|\
    */audit/corpus_tags/tags/*.md|\
    */audit/corpus_tags/derived/*.jsonl|\
    */audit/corpus_tags/derived/*.json|\
    */obsidian-vault/anti-patterns/*.md|\
    */obsidian-vault/anti-patterns/*.yaml|\
    */obsidian-vault/mining/*.md|\
    */reference/patterns.dsl*/*.yaml)
      return 0
      ;;
    *)
      return 1
      ;;
  esac
}

if ! is_corpus_path "${file_path}"; then
  [[ "${AUDITOOOR_CORPUS_REFRESH_HOOK_VERBOSE:-0}" == "1" ]] && emit_log "skipped-non-corpus-path" "path does not match corpus globs" "${file_path}"
  exit 0
fi

# Throttle: if the last successful trigger is within THROTTLE_SECONDS, skip.
now_epoch="$(date +%s 2>/dev/null || echo 0)"
last_epoch=0
if [[ -f "${THROTTLE_FILE}" ]]; then
  last_epoch="$(cat "${THROTTLE_FILE}" 2>/dev/null | head -c 32 | tr -dc '0-9' || true)"
  last_epoch="${last_epoch:-0}"
fi
delta=$(( now_epoch - last_epoch ))
if (( last_epoch > 0 && delta < THROTTLE_SECONDS )); then
  emit_log "skipped-throttled" "throttle ${delta}s < ${THROTTLE_SECONDS}s" "${file_path}"
  exit 0
fi

# Record this trigger BEFORE spawning refresh -- a second trigger arriving
# while the refresh is still running will then see the updated timestamp
# and skip without piling on.
printf '%s' "${now_epoch}" > "${THROTTLE_FILE}" 2>/dev/null || true

emit_log "fired" "corpus-path matched + throttle ok" "${file_path}"

# LIFT-26 / R67: shrinkage detection. If the touched corpus file shrunk
# more than 50% since its last rotation_log entry AND there is no fresh
# rotation_log entry recording the change, emit an R67 violation. The
# tool refuses to fail-block (hook stays fail-open); the violation is
# audit-logged.
# r36-rebuttal: lane-LIFT-26-R67 in agent_pathspec.json
r67_check() {
  local target="$1"
  local verifier="${REPO_ROOT}/tools/r67-rotation-cursor-verifier.py"
  if [[ ! -f "${verifier}" ]]; then
    return 0
  fi
  if [[ ! -f "${target}" ]]; then
    return 0
  fi
  # Skip rotation logs / backups / tmpfiles themselves.
  case "${target}" in
    *.rotation_log.jsonl|*.bak.*|*.tmp.*) return 0 ;;
  esac
  local result
  result="$(python3 "${verifier}" --file "${target}" --json 2>/dev/null)"
  if [[ -z "${result}" ]]; then
    return 0
  fi
  local verdict
  verdict="$(printf '%s' "${result}" | python3 -c '
import json, sys
try:
    d = json.load(sys.stdin)
    rs = d.get("results", [])
    if rs:
        print(rs[0].get("verdict", ""))
except Exception:
    print("")
' 2>/dev/null)"
  case "${verdict}" in
    fail-shrinkage-over-50pct-no-log-entry)
      emit_log "r67-violation-shrinkage" \
        "R67 shrinkage>50pct without rotation_log entry; migrate writer to atomic_corpus_writer" \
        "${target}"
      ;;
    warn-no-rotation-log)
      [[ "${AUDITOOOR_CORPUS_REFRESH_HOOK_VERBOSE:-0}" == "1" ]] && \
        emit_log "r67-warn-no-rotation-log" "no rotation_log sibling exists for this corpus file" "${target}"
      ;;
  esac
  return 0
}

r67_check "${file_path}"

# Refresh body. Each step is fail-open (errors logged, never propagated).
run_refresh() {
  local rc=0
  local out_inv out_inv_idx
  # Step A: refresh corpus inventory snapshot. corpus-inventory.py supports
  # --summary --out <path>; we write to a stable location so downstream
  # vault callables that read the latest inventory see fresh stats.
  out_inv="${LOG_DIR}/corpus_refresh_last_inventory.json"
  if python3 "${REPO_ROOT}/tools/corpus-inventory.py" --summary --out "${out_inv}" >/dev/null 2>&1; then
    emit_log "refresh-step-ok" "corpus-inventory snapshot refreshed" "${out_inv}"
  else
    rc=$?
    emit_log "refresh-step-error" "corpus-inventory rc=${rc}" "${out_inv}"
  fi

  # Step B: rebuild the invariant library index (consumed by
  # vault_invariant_library + make audit-deep).
  out_inv_idx="${REPO_ROOT}/audit/corpus_tags/derived/invariant_library_index.json"
  if python3 "${REPO_ROOT}/tools/llm-extract-invariants.py" --build-index >/dev/null 2>&1; then
    emit_log "refresh-step-ok" "invariant-library index rebuilt" "${out_inv_idx}"
  else
    rc=$?
    emit_log "refresh-step-error" "llm-extract-invariants --build-index rc=${rc}" "${out_inv_idx}"
  fi

  # Step C (added 2026-05-27 / mimo-harness-build wave): auto-flow killed
  # MIMO candidates into reports/known_dead_ends.jsonl when a MIMO sidecar
  # write occurred. Idempotent (dedupes by record_id). Only fires when the
  # touched path matches audit/corpus_tags/derived/mimo_harness* OR mega*
  # to avoid recomputing on unrelated corpus writes.
  # G14 (2026-05-28): workflow/Agent drill sidecars land under
  # audit/corpus_tags/derived/mimo_harness_<ws>_workflow/, which MATCHES the
  # mimo_harness* glob below - no glob edit needed; workflow kills auto-flow.
  case "${file_path}" in
    *audit/corpus_tags/derived/mimo_harness*|*audit/corpus_tags/derived/mega*)
      if python3 "${REPO_ROOT}/tools/triage-kill-promoter.py" --json >/dev/null 2>&1; then
        emit_log "refresh-step-ok" "kill-promoter auto-flow" "reports/known_dead_ends.jsonl"
      else
        rc=$?
        emit_log "refresh-step-error" "triage-kill-promoter rc=${rc}" "reports/known_dead_ends.jsonl"
      fi
      ;;
  esac

  # Step D (added 2026-05-27): R76 hallucination scan over the touched
  # mimo_harness/mega sidecar dir. Output stays in
  # .auditooor/r76_hallucination_scan_<dir>.json so vault_mining_health
  # can surface fresh counts without re-scanning. Best-effort, fail-open.
  # G14 (2026-05-28): workflow sidecar dirs (mimo_harness_<ws>_workflow)
  # MATCH the mimo_harness* glob below, so they are R76-scanned here too -
  # a belt-and-braces check on top of the emit-time R76 downgrade in
  # tools/workflow-drill-sidecar-emit.py.
  case "${file_path}" in
    *audit/corpus_tags/derived/mimo_harness*|*audit/corpus_tags/derived/mega*)
      _scan_dir="$(dirname "${file_path}")"
      _safe_name="$(printf '%s' "${_scan_dir}" | tr '/' '_' | tr -cd '[:alnum:]_')"
      _out="${LOG_DIR}/r76_hallucination_scan_${_safe_name}.json"
      if python3 "${REPO_ROOT}/tools/r76-hallucination-guard.py" \
           --scan-mimo-dir "${_scan_dir}" --json > "${_out}" 2>/dev/null; then
        emit_log "refresh-step-ok" "r76 hallucination scan" "${_out}"
      else
        rc=$?
        emit_log "refresh-step-error" "r76-hallucination-guard rc=${rc}" "${_out}"
      fi
      ;;
  esac

  emit_log "refresh-complete" "rc=${rc}" "${file_path}"
}

if [[ "${AUDITOOOR_CORPUS_REFRESH_HOOK_SYNC:-0}" == "1" ]]; then
  run_refresh
else
  # Spawn detached so we never block the original write.
  (
    run_refresh
  ) </dev/null >/dev/null 2>&1 &
  disown 2>/dev/null || true
fi

exit 0
