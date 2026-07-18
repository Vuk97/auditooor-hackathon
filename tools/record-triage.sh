#!/usr/bin/env bash
# record-triage.sh — log a detector triage decision to _hits_ledger.yaml (Issue #83)
#
# Every triage decision logs one row. Each detector accumulates (TP, FP,
# UNKNOWN) counts. Precision = TP / (TP + FP). Drives tier promotion via
# `tools/detector-tier.sh audit`.
#
# Usage:
#   ./tools/record-triage.sh <detector> <workspace> <finding-id> <verdict> [severity]
#
#   verdicts: TP | FP | UNKNOWN
#   severity (for TP): Critical | High | Medium | Low | Info
#
# Example:
#   ./tools/record-triage.sh role-grant-divergence polymarket OFF.A TP High
#   ./tools/record-triage.sh callback-reentrancy-no-guard morpho fn-abc FP
#
# The tool is idempotent: repeated (detector, workspace, finding) tuples
# overwrite prior verdicts for that row (allows correcting a mistake).

set -uo pipefail

AUDITOOOR_DIR="$(cd "$(dirname "$0")/.." && pwd)"
LEDGER="$AUDITOOOR_DIR/detectors/_hits_ledger.yaml"

if [ $# -lt 4 ]; then
    sed -n '2,20p' "$0" | sed 's/^# //; s/^#//'
    exit 1
fi

DETECTOR="$1"
WORKSPACE="$2"
FINDING="$3"
VERDICT="$(echo "$4" | tr '[:lower:]' '[:upper:]')"
SEVERITY="${5:-}"

case "$VERDICT" in
    TP|FP|UNKNOWN) ;;
    *) echo "[error] verdict must be TP / FP / UNKNOWN (got: $VERDICT)" >&2; exit 1 ;;
esac

python3 - "$LEDGER" "$DETECTOR" "$WORKSPACE" "$FINDING" "$VERDICT" "$SEVERITY" <<'PY'
import sys, datetime
from pathlib import Path

try:
    import yaml  # type: ignore
except ImportError:
    yaml = None

ledger_path = Path(sys.argv[1])
detector = sys.argv[2]
workspace = sys.argv[3]
finding = sys.argv[4]
verdict = sys.argv[5]
severity = sys.argv[6] if sys.argv[6] else None

def parse_scalar(value):
    value = value.strip()
    if value in ("[]", ""):
        return []
    if value in ("{}",):
        return {}
    if value in ("null", "Null", "NULL", "~"):
        return None
    if value in ("true", "True", "TRUE"):
        return True
    if value in ("false", "False", "FALSE"):
        return False
    if (value.startswith("'") and value.endswith("'")) or (
        value.startswith('"') and value.endswith('"')
    ):
        return value[1:-1]
    try:
        return int(value)
    except ValueError:
        pass
    try:
        return float(value)
    except ValueError:
        return value


def load_hits_ledger(path):
    if not path.exists():
        return {"version": 1, "detectors": {}}
    text = path.read_text()
    if yaml is not None:
        return yaml.safe_load(text) or {"version": 1, "detectors": {}}

    # Minimal stdlib parser for auditooor's own _hits_ledger.yaml shape. This
    # keeps record-triage usable on PEP-668/system Python installs without
    # silently dropping telemetry just because PyYAML is absent.
    data = {"version": 1, "detectors": {}}
    current_detector = None
    current_list = None
    current_item = None
    for raw in text.splitlines():
        line = raw.split("#", 1)[0].rstrip()
        if not line.strip():
            continue
        indent = len(raw) - len(raw.lstrip(" "))
        stripped = line.strip()
        if indent == 0:
            key, sep, value = stripped.partition(":")
            if sep and value.strip():
                data[key] = parse_scalar(value)
            continue
        if indent == 2 and stripped.endswith(":"):
            current_detector = stripped[:-1]
            data.setdefault("detectors", {}).setdefault(current_detector, {})
            current_list = None
            current_item = None
            continue
        if current_detector is None:
            continue
        entry = data.setdefault("detectors", {}).setdefault(current_detector, {})
        if current_list and stripped.startswith("- "):
            item_text = stripped[2:].strip()
            current_item = {}
            entry.setdefault(current_list, []).append(current_item)
            if item_text:
                key, sep, value = item_text.partition(":")
                if sep:
                    current_item[key.strip()] = parse_scalar(value)
            continue
        if indent == 4:
            key, sep, value = stripped.partition(":")
            if not sep:
                continue
            key = key.strip()
            value = value.strip()
            if value == "":
                entry[key] = []
                current_list = key
                current_item = None
            else:
                entry[key] = parse_scalar(value)
                current_list = None
                current_item = None
            continue
        if current_item is not None and ":" in stripped:
            key, _, value = stripped.partition(":")
            current_item[key.strip()] = parse_scalar(value)
    return data


def dump_scalar(value):
    if value is None:
        return "null"
    if isinstance(value, bool):
        return "true" if value else "false"
    if isinstance(value, (int, float)):
        return str(value)
    text = str(value)
    if not text or text.lower() in {"true", "false", "null"} or text[0] in "{}[]#&*!|>'\"%@`":
        return repr(text)
    if ":" in text or text.startswith(" ") or text.endswith(" "):
        return repr(text)
    return text


def dump_hits_ledger(data):
    if yaml is not None:
        return yaml.safe_dump(data, sort_keys=False)
    lines = [f"version: {dump_scalar(data.get('version', 1))}", "detectors:"]
    for detector, entry in (data.get("detectors") or {}).items():
        lines.append(f"  {detector}:")
        for key in ("hits", "tp", "fp", "unknown", "precision"):
            lines.append(f"    {key}: {dump_scalar(entry.get(key, 0))}")
        for key in ("real_catches", "_history"):
            rows = entry.get(key) or []
            lines.append(f"    {key}:")
            if not rows:
                lines[-1] += " []"
                continue
            for row in rows:
                first = True
                for rkey, rval in row.items():
                    prefix = "      - " if first else "        "
                    lines.append(f"{prefix}{rkey}: {dump_scalar(rval)}")
                    first = False
        lines.append(f"    last_updated: {dump_scalar(entry.get('last_updated'))}")
    return "\n".join(lines) + "\n"


# Load ledger
data = load_hits_ledger(ledger_path)

dets = data.setdefault("detectors", {})
entry = dets.setdefault(detector, {
    "hits": 0, "tp": 0, "fp": 0, "unknown": 0, "precision": 0.0,
    "real_catches": [], "last_updated": None
})

# Check for prior entry for this (workspace, finding) tuple; remove stale.
catches = entry.get("real_catches", [])
removed = None
new_catches = []
for c in catches:
    if c.get("workspace") == workspace and c.get("finding") == finding:
        removed = c
        continue
    new_catches.append(c)
entry["real_catches"] = new_catches

# If prior verdict existed for this (ws, finding), decrement its count first.
# We track prior verdict implicitly via (real_catches) for TP; FP/UNKNOWN
# aren't in real_catches. Simpler: store history in a hidden list.
history = entry.setdefault("_history", [])
for h in list(history):
    if h.get("workspace") == workspace and h.get("finding") == finding:
        prev = h.get("verdict")
        if prev == "TP":
            entry["tp"] = max(0, entry.get("tp", 0) - 1)
        elif prev == "FP":
            entry["fp"] = max(0, entry.get("fp", 0) - 1)
        elif prev == "UNKNOWN":
            entry["unknown"] = max(0, entry.get("unknown", 0) - 1)
        entry["hits"] = max(0, entry.get("hits", 0) - 1)
        history.remove(h)

# Now apply the new verdict
entry["hits"] = entry.get("hits", 0) + 1
if verdict == "TP":
    entry["tp"] = entry.get("tp", 0) + 1
    new_catches.append({
        "workspace": workspace,
        "finding": finding,
        "severity": severity or "Unknown",
        "date": datetime.date.today().isoformat(),
    })
    entry["real_catches"] = new_catches
elif verdict == "FP":
    entry["fp"] = entry.get("fp", 0) + 1
else:
    entry["unknown"] = entry.get("unknown", 0) + 1

history.append({
    "workspace": workspace,
    "finding": finding,
    "verdict": verdict,
    "date": datetime.date.today().isoformat(),
})
entry["_history"] = history

# Recompute precision
tp = entry.get("tp", 0)
fp = entry.get("fp", 0)
if tp + fp > 0:
    entry["precision"] = round(tp / (tp + fp), 3)
else:
    entry["precision"] = 0.0

entry["last_updated"] = datetime.date.today().isoformat()
dets[detector] = entry

ledger_path.write_text(dump_hits_ledger(data))

print(f"[ok] recorded: {detector} × {workspace}/{finding} = {verdict}" +
      (f" ({severity})" if severity else ""))
print(f"  totals: {entry['tp']} TP / {entry['fp']} FP / {entry['unknown']} unknown  " +
      f"(precision={entry['precision']:.2f}, wins={len(entry['real_catches'])})")
if removed:
    print(f"  (superseded prior TP entry for {workspace}/{finding})")
PY
