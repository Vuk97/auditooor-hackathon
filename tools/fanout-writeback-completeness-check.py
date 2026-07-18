#!/usr/bin/env python3
"""Fail-closed check that every dispatched fan-out worklist unit produced a
written sidecar before the bridge trusts coverage.

Root cause (24h retrospective): an agent dispatched a 24-unit batch but wrote
only 7 sidecars = silent under-coverage (the "7/24 pattern"). This check
enumerates every unit named by a dispatched worklist file, then checks the
workspace's hunt-findings sidecar tree for a matching non-empty sidecar.
Any dispatched unit with no (or a zero-byte) sidecar is reported MISSING -
unknown mapping is always treated as missing, never a silent pass.

Generic across all workspaces/languages: worklist units and sidecar rows are
matched purely on `basename(file)::function` identity strings, tolerant of a
flat schema ({unit,file,function,lines}) or a nested schema
({result:{function_anchor:...}}).

CLI:
    python3 tools/fanout-writeback-completeness-check.py --workspace <ws> \
        [--worklist <path/glob>] [--sidecar-dir <dir>] [--json] [--strict]

Never-false-pass contract:
    - No worklist files found at all              -> pass-no-worklist (rc 0)
    - Worklist non-empty, sidecars fully cover it  -> pass-writeback-complete (rc 0)
    - Worklist non-empty, coverage incomplete      -> fail-writeback-incomplete
                                                       (rc 1 iff --strict, else rc 0 advisory)
    - Fail-OPEN only on genuine absence of worklist inputs; NEVER fail-open
      just because sidecars are missing/empty when a worklist exists.
"""
from __future__ import annotations

import argparse
import glob as globmod
import json
import re
import sys
from pathlib import Path
from typing import Any, Iterable

SCHEMA = "auditooor.fanout_writeback_completeness.v1"

DEFAULT_WORKLIST_GLOBS = [
    ".auditooor/*_part_*.txt",
    ".auditooor/hollow_*.txt",
    ".auditooor/qns_*.txt",
    ".auditooor/agent_batch_*.md",
    ".auditooor/*.residual.jsonl",
]

DEFAULT_SIDECAR_GLOBS = [
    ".auditooor/hunt_findings_sidecars/**/*.json",
    ".auditooor/**/*sidecar*/**/*.json",
    ".auditooor/**/*sidecar*.json",
]

# Matches "path/to/File.sol::functionName" or "...::functionName::123"
UNIT_LINE_RE = re.compile(
    r"(?P<file>[\w./\\-]+\.\w+)\s*::\s*(?P<function>[A-Za-z_][\w]*)(?:\s*::\s*(?P<line>\d+))?"
)


def _basename(path: str) -> str:
    return Path(path.replace("\\", "/")).name


def _unit_key(file_part: str, function_part: str) -> str:
    return f"{_basename(file_part)}::{function_part}".strip()


def _expand_globs(workspace: Path, patterns: Iterable[str]) -> list[Path]:
    out: list[Path] = []
    for pat in patterns:
        pat_path = pat if Path(pat).is_absolute() else str(workspace / pat)
        for hit in globmod.glob(pat_path, recursive=True):
            p = Path(hit)
            if p.is_file():
                out.append(p)
    # de-dupe, preserve order
    seen = set()
    uniq = []
    for p in out:
        rp = str(p.resolve())
        if rp not in seen:
            seen.add(rp)
            uniq.append(p)
    return uniq


def _extract_units_from_text(text: str) -> list[str]:
    units: list[str] = []
    for line in text.splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        for m in UNIT_LINE_RE.finditer(line):
            key = _unit_key(m.group("file"), m.group("function"))
            if key and key != "::":
                units.append(key)
    return units


def _extract_units_from_jsonl(text: str) -> list[str]:
    units: list[str] = []
    for line in text.splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            row = json.loads(line)
        except (json.JSONDecodeError, ValueError):
            # Fall back to regex extraction on the raw line.
            units.extend(_extract_units_from_text(line))
            continue
        key = _unit_key_from_obj(row)
        if key:
            units.append(key)
    return units


def _unit_key_from_obj(row: Any) -> str | None:
    if not isinstance(row, dict):
        return None
    # Flat schema: {unit, file, function, lines}
    if "unit" in row and isinstance(row["unit"], str) and "::" in row["unit"]:
        parts = row["unit"].split("::")
        if len(parts) >= 2:
            return _unit_key(parts[0], parts[1])
    file_part = row.get("file") or row.get("file_path") or row.get("path")
    func_part = row.get("function") or row.get("fn") or row.get("function_name")
    if file_part and func_part:
        return _unit_key(str(file_part), str(func_part))
    # Nested schema: {result: {function_anchor: "file::fn" or {...}}}
    result = row.get("result")
    if isinstance(result, dict):
        anchor = result.get("function_anchor")
        if isinstance(anchor, str) and "::" in anchor:
            parts = anchor.split("::")
            if len(parts) >= 2:
                return _unit_key(parts[0], parts[1])
        if isinstance(anchor, dict):
            f = anchor.get("file") or anchor.get("file_path")
            fn = anchor.get("function") or anchor.get("function_name")
            if f and fn:
                return _unit_key(str(f), str(fn))
    return None


def collect_worklist_units(workspace: Path, worklist_patterns: list[str] | None) -> tuple[list[str], list[str]]:
    """Return (units, worklist_files_scanned)."""
    patterns = worklist_patterns if worklist_patterns else DEFAULT_WORKLIST_GLOBS
    files = _expand_globs(workspace, patterns)
    units: list[str] = []
    scanned: list[str] = []
    for f in files:
        try:
            text = f.read_text(errors="replace")
        except OSError:
            continue
        scanned.append(str(f))
        if f.suffix == ".jsonl":
            units.extend(_extract_units_from_jsonl(text))
        else:
            units.extend(_extract_units_from_text(text))
    # de-dupe, preserve order
    seen = set()
    uniq = []
    for u in units:
        if u not in seen:
            seen.add(u)
            uniq.append(u)
    return uniq, scanned


def collect_sidecar_units(workspace: Path, sidecar_dir: str | None) -> set[str]:
    patterns = [str(Path(sidecar_dir) / "**" / "*.json")] if sidecar_dir else DEFAULT_SIDECAR_GLOBS
    files = _expand_globs(workspace, patterns)
    covered: set[str] = set()
    for f in files:
        try:
            if f.stat().st_size == 0:
                continue  # zero-byte sidecar never counts as coverage
        except OSError:
            continue
        try:
            raw = f.read_text(errors="replace")
        except OSError:
            continue
        if not raw.strip():
            continue
        try:
            data = json.loads(raw)
        except (json.JSONDecodeError, ValueError):
            continue
        rows = data if isinstance(data, list) else [data]
        for row in rows:
            key = _unit_key_from_obj(row)
            if key:
                covered.add(key)
    return covered


def run_check(workspace: Path, worklist_patterns: list[str] | None, sidecar_dir: str | None) -> dict:
    units, worklists_scanned = collect_worklist_units(workspace, worklist_patterns)

    if not units:
        return {
            "schema": SCHEMA,
            "verdict": "pass-no-worklist",
            "dispatched": 0,
            "written": 0,
            "missing": [],
            "worklists_scanned": worklists_scanned,
        }

    covered = collect_sidecar_units(workspace, sidecar_dir)
    missing = [u for u in units if u not in covered]
    written_count = len(units) - len(missing)

    verdict = "pass-writeback-complete" if not missing else "fail-writeback-incomplete"

    return {
        "schema": SCHEMA,
        "verdict": verdict,
        "dispatched": len(units),
        "written": written_count,
        "missing": missing,
        "worklists_scanned": worklists_scanned,
    }


def _write_artifact(workspace: Path, result: dict) -> Path:
    out_dir = workspace / ".auditooor"
    out_dir.mkdir(parents=True, exist_ok=True)
    out_path = out_dir / "fanout_writeback_completeness.json"
    out_path.write_text(json.dumps(result, indent=2) + "\n")
    return out_path


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--workspace", required=True, help="Workspace root path")
    ap.add_argument("--worklist", action="append", default=None,
                     help="Worklist path or glob (repeatable). Defaults to the standard fan-out patterns.")
    ap.add_argument("--sidecar-dir", default=None, help="Sidecar directory root (defaults to standard hunt-findings-sidecar locations)")
    ap.add_argument("--json", action="store_true", help="Emit JSON result to stdout")
    ap.add_argument("--strict", action="store_true", help="Exit rc=1 on incompleteness (default: advisory rc=0)")
    args = ap.parse_args()

    workspace = Path(args.workspace).resolve()
    result = run_check(workspace, args.worklist, args.sidecar_dir)

    try:
        _write_artifact(workspace, result)
    except OSError:
        pass

    if result["verdict"] == "fail-writeback-incomplete":
        sample = result["missing"][:10]
        print(
            f"Dispatched {result['dispatched']}, found {result['written']} "
            f"({len(result['missing'])} missing). Missing sample: {sample}. "
            f"Re-dispatch missing before bridging (7-of-24 pattern)."
        )
    elif result["verdict"] == "pass-writeback-complete":
        print(f"Dispatched {result['dispatched']}, found {result['written']} (0 missing). pass-writeback-complete")
    else:
        print("pass-no-worklist")

    if args.json:
        print(json.dumps(result, indent=2))

    if result["verdict"] == "fail-writeback-incomplete" and args.strict:
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
