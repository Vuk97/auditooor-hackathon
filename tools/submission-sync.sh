#!/usr/bin/env bash
# submission-sync.sh — summarize STATUS.md counts from the active submission ledger
#
# Usage:
#   ./tools/submission-sync.sh <workspace-dir> [--apply-status]
#
# Resolves the active workspace submission ledger (nested or root-level),
# parses already-filed findings, and prints a STATUS.md-friendly summary plus
# a ready-to-paste "Confirmed findings" line. Operator pastes into STATUS.md
# manually (or this script can be wired into append-iter.sh). Also understands
# the older `**Confirmed findings:** N` header shape when checking drift.
#
# Fixes SKILL_ISSUES.md #74.

set -uo pipefail

usage() {
    cat <<'EOF'
submission-sync.sh — summarize STATUS.md counts from the active submission ledger

Usage:
  ./tools/submission-sync.sh <workspace-dir> [--apply-status]

What it does:
  - resolves the active submission ledger (`submissions/SUBMISSIONS.md` or root `SUBMISSIONS.md`)
  - prints filed findings, severity/status breakdowns, and a ready-to-paste
    `**Confirmed findings (...)**` STATUS.md line
  - checks the current STATUS.md header for drift, including the older
    `**Confirmed findings:** N` shape
  - with `--apply-status`, rewrites the STATUS.md confirmed-findings header
    to match the active submission ledger
EOF
}

if [ $# -lt 1 ]; then
    usage
    exit 1
fi

case "${1:-}" in
    -h|--help)
        usage
        exit 0
        ;;
esac

WS="$1"
APPLY_STATUS=0
shift || true

while [ "$#" -gt 0 ]; do
    case "$1" in
        --apply-status) APPLY_STATUS=1; shift ;;
        *) echo "[error] unknown argument: $1" >&2; usage; exit 1 ;;
    esac
done

python3 - "$WS" "$APPLY_STATUS" <<'PY'
import re
import sys
from collections import Counter
from pathlib import Path

repo_tools = Path.cwd() / "tools"
sys.path.insert(0, str(repo_tools))

from submission_ledger import load_submission_entries, strip_markdown
from submission_paths import find_submission_file, submission_file_location

ws = Path(sys.argv[1])
apply_status = sys.argv[2] == "1"
tracker = find_submission_file(ws)
if tracker is None or not tracker.exists():
    print(f"[error] no submission ledger found under {ws}", file=sys.stderr)
    sys.exit(1)

entries = load_submission_entries(tracker)

def normalize_severity(value: str) -> str:
    sev = strip_markdown(value).title()
    if sev in {"Critical", "High", "Medium", "Low"}:
        return sev
    return "Unknown"

def status_bucket(value: str) -> str:
    status = strip_markdown(value).lower()
    if not status:
        return "unknown"
    if "review" in status:
        return "in_review"
    if "duplicate" in status or "dupe" in status:
        return "duplicate"
    if "paid" in status:
        return "paid"
    if "reject" in status:
        return "rejected"
    if "pending" in status or "submitted" in status:
        return "pending"
    return status.replace(" ", "_")

severity_counts = Counter()
status_counts = Counter()
for entry in entries:
    severity_counts[normalize_severity(entry.get("severity", ""))] += 1
    status_counts[status_bucket(entry.get("status", ""))] += 1

total = len(entries)
print(f"=== submission-sync: {ws} ===")
print("")
print(f"  Active tracker: {tracker} ({submission_file_location(ws)})")
print(f"  Findings ({total} filed):")
for entry in entries:
    fid = entry.get("id") or "?"
    sev = normalize_severity(entry.get("severity", ""))
    status = strip_markdown(entry.get("status", "")) or "?"
    title = (entry.get("title") or "<untitled>").strip()
    print(f"    #{fid:<6} {sev:<8} {status:<18} {title}")

critical = severity_counts["Critical"]
high = severity_counts["High"]
medium = severity_counts["Medium"]
low = severity_counts["Low"]
unknown = severity_counts["Unknown"]
print("")
breakdown = f"  Breakdown: {critical}C + {high}H + {medium}M + {low}L"
if unknown:
    breakdown += f" + {unknown} unknown"
breakdown += f" = {total} filed"
print(breakdown)

if status_counts:
    ordered = []
    preferred = ["pending", "in_review", "duplicate", "paid", "rejected", "unknown"]
    for key in preferred:
        if status_counts.get(key):
            ordered.append(f"{status_counts[key]} {key.replace('_', ' ')}")
    for key in sorted(status_counts):
        if key not in preferred:
            ordered.append(f"{status_counts[key]} {key.replace('_', ' ')}")
    print(f"  Status:    {', '.join(ordered)}")
print("")

severity_parts = []
if critical:
    severity_parts.append(f"{critical} Critical")
if high:
    severity_parts.append(f"{high} High")
if medium:
    severity_parts.append(f"{medium} Medium")
if low:
    severity_parts.append(f"{low} Low")
if unknown:
    severity_parts.append(f"{unknown} Unknown")

status_parts = []
for key in ["pending", "in_review", "duplicate", "paid", "rejected"]:
    if status_counts.get(key):
        status_parts.append(f"{status_counts[key]} {key.replace('_', ' ')}")
for key in sorted(status_counts):
    if key not in {"pending", "in_review", "duplicate", "paid", "rejected"}:
        status_parts.append(f"{status_counts[key]} {key.replace('_', ' ')}")

summary_line = f"**Confirmed findings ({total} filed"
if severity_parts:
    summary_line += " — " + ", ".join(severity_parts)
if status_parts:
    summary_line += "; " + ", ".join(status_parts)
summary_line += "):**"

print("  Suggested STATUS.md line:")
print(f"    {summary_line}")
print("")

status_md = ws / "STATUS.md"
if status_md.exists():
    status_text = status_md.read_text()
    match = re.search(r"\*\*Confirmed findings \((\d+)\s+(submitted|filed)", status_text)
    if not match:
        match = re.search(r"\*\*Confirmed findings:\*\*\s*(\d+)", status_text)
    if match:
        status_count = int(match.group(1))
        if status_count != total:
            print(f"  [DRIFT] STATUS.md says {status_count} submitted but the active ledger has {total} filed findings")
            print("          Update the STATUS.md header to match.")
        else:
            print("  [ok] STATUS.md confirmed-findings count matches the active ledger")
    else:
        print("  [info] STATUS.md found, but no 'Confirmed findings (N submitted/filed ...)' header was detected")
    if apply_status:
        new_text, count = re.subn(
            r"^\*\*Confirmed findings(?: \([^)]+\))?:\*\*.*$",
            summary_line,
            status_text,
            count=1,
            flags=re.MULTILINE,
        )
        if count == 0:
            print("  [apply-status] no compatible STATUS.md confirmed-findings header found", file=sys.stderr)
            sys.exit(2)
        if new_text != status_text:
            status_md.write_text(new_text)
            print(f"  [apply-status] updated {status_md}")
        else:
            print(f"  [apply-status] {status_md} already matched the active ledger")
elif apply_status:
    print(f"  [apply-status] no STATUS.md found under {ws}", file=sys.stderr)
    sys.exit(2)
PY
