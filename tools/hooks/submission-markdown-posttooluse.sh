#!/usr/bin/env bash
# submission-markdown-posttooluse.sh — Claude Code PostToolUse hook
#
# Triggered after Edit / Write / MultiEdit / NotebookEdit tool calls. Runs the
# lightweight pre-submit watchdog when a submission markdown file changes.
#
# Staging drafts are advisory by default. Paste-ready/package/final-paste
# paths are strict by default. Set AUDITOOOR_SUBMISSION_HOOK_ADVISORY=1 to
# force advisory mode, or AUDITOOOR_SUBMISSION_HOOK_STRICT=1 to force strict.

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/../.." && pwd)"
LOG_DIR="${REPO_ROOT}/.auditooor"
LOG_FILE="${LOG_DIR}/submission-markdown-hook.jsonl"
WATCHDOG="${REPO_ROOT}/tools/pre-submit-watchdog.py"
L33_CHECKER="${REPO_ROOT}/tools/l33-changelog-drift-check.py"

payload="$(cat)"

tool_name="$(printf '%s' "${payload}" | python3 -c \
  "import sys,json; d=json.load(sys.stdin); print(d.get('tool_name',''))" 2>/dev/null || true)"

file_path="$(printf '%s' "${payload}" | python3 -c \
  "import sys,json; d=json.load(sys.stdin); ti=d.get('tool_input',{}) or {}; print(ti.get('file_path') or ti.get('path') or '')" 2>/dev/null || true)"

case "${tool_name}" in
  Edit|Write|MultiEdit|NotebookEdit) ;;
  *) exit 0 ;;
esac

if [[ -z "${file_path}" ]]; then
  exit 0
fi

if [[ "${file_path}" != /* ]]; then
  file_path="${REPO_ROOT}/${file_path}"
fi

case "${file_path}" in
  */submissions/staging/*.md|\
  */submissions/paste_ready/*.md|\
  */submissions/paste_ready/current/*.md|\
  */submissions/held/*.md|\
  */submissions/packaged/*.md|\
  */submissions/clean/*.md|\
  */submissions/engage_candidates/clean/*.md|\
  */final_cantina_paste/*.md|\
  */submissions/SUBMISSIONS.md)
    ;;
  *)
    exit 0
    ;;
esac

workspace="$(python3 - "${file_path}" <<'PY'
import sys
from pathlib import Path

path = Path(sys.argv[1]).expanduser().resolve()
for parent in [path.parent, *path.parents]:
    if (parent / "submissions").is_dir() or (parent / "poc-tests").is_dir():
        print(parent)
        raise SystemExit(0)
print(path.parent)
PY
)"

cmd=(python3 "${WATCHDOG}" "${workspace}" --mode quick --changed "${file_path}" --json)
strict_default=0
case "${file_path}" in
  */submissions/paste_ready/*.md|\
  */submissions/paste_ready/current/*.md|\
  */submissions/packaged/*.md|\
  */final_cantina_paste/*.md)
    strict_default=1
    ;;
esac

advisory_mode=0
if [[ "${AUDITOOOR_SUBMISSION_HOOK_ADVISORY:-0}" == "1" ]]; then
  advisory_mode=1
elif [[ "${AUDITOOOR_SUBMISSION_HOOK_STRICT:-0}" == "1" || "${strict_default}" == "1" ]]; then
  advisory_mode=0
else
  advisory_mode=1
fi

if [[ "${advisory_mode}" == "1" ]]; then
  cmd+=(--advisory)
fi

if [[ "${DRY_RUN:-0}" == "1" ]]; then
  echo "would-run: ${cmd[*]}"
  if [[ -f "${L33_CHECKER}" ]]; then
    l33_probe="$(python3 "${L33_CHECKER}" "${file_path}" --mode hook --json 2>/dev/null || true)"
    l33_triggered="$(
      printf '%s' "${l33_probe}" | python3 -c \
        'import json,sys
try:
    payload=json.load(sys.stdin)
except Exception:
    print("0")
else:
    print("1" if payload.get("triggered") else "0")'
    )"
    if [[ "${l33_triggered}" == "1" ]]; then
      echo "would-run: python3 ${L33_CHECKER} ${file_path} --mode hook --write-sidecar"
    fi
  fi
  exit 0
fi

mkdir -p "${LOG_DIR}"
tmp_out="$(mktemp 2>/dev/null || echo "/tmp/submission_markdown_hook_$$.json")"
tmp_err="$(mktemp 2>/dev/null || echo "/tmp/submission_markdown_hook_$$.err")"

set +e
"${cmd[@]}" > "${tmp_out}" 2> "${tmp_err}"
rc=$?
set -euo pipefail

python3 - "${LOG_FILE}" "${tool_name}" "${file_path}" "${workspace}" "${rc}" "${tmp_out}" "${tmp_err}" <<'PY'
import json
import sys
from datetime import datetime, timezone
from pathlib import Path

log_path = Path(sys.argv[1])
tool_name = sys.argv[2]
file_path = sys.argv[3]
workspace = sys.argv[4]
rc = int(sys.argv[5])
out_path = Path(sys.argv[6])
err_path = Path(sys.argv[7])

try:
    payload = json.loads(out_path.read_text(encoding="utf-8"))
except Exception:
    payload = {
        "status": "error",
        "stdout": out_path.read_text(encoding="utf-8", errors="replace")[:2000],
    }
err = err_path.read_text(encoding="utf-8", errors="replace").strip()
row = {
    "ts": datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z"),
    "hook": "submission-markdown-posttooluse",
    "tool_name": tool_name,
    "file": file_path,
    "workspace": workspace,
    "exit_code": rc,
    "status": payload.get("status"),
    "failed_count": payload.get("failed_count"),
    "summary": payload,
}
if err:
    row["stderr"] = err[:2000]
log_path.parent.mkdir(parents=True, exist_ok=True)
with log_path.open("a", encoding="utf-8") as fh:
    fh.write(json.dumps(row, sort_keys=True) + "\n")
PY

if [[ -f "${L33_CHECKER}" ]]; then
  set +e
  python3 "${L33_CHECKER}" "${file_path}" --mode hook --write-sidecar >/dev/null 2>&1
  set -euo pipefail
fi

if [[ "${advisory_mode}" != "1" ]]; then
  rm -f "${tmp_out}" "${tmp_err}"
  exit "${rc}"
fi

rm -f "${tmp_out}" "${tmp_err}"
exit 0
