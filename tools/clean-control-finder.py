#!/usr/bin/env python3
"""Clean sibling/control finder for High/Critical exploit-queue proof artifacts.

Plan item C6 from docs/HACKERMAN_V3_CAPABILITY_PLAN_2026-05-19.md:

  Every serious exploit hypothesis needs a clean control: sibling function,
  sibling protocol version, unaffected asset, or clean deployment config that
  proves the claimed vulnerable path is materially different. Acceptance:
  High/Critical proof artifacts include vulnerable_path, clean_control_path,
  and material_difference.

This tool reads the workspace exploit queue (and optional source proofs) and
for each High/Critical row checks whether it carries all three fields.  When
they are absent it PROPOSES candidate clean controls via four heuristics:

  (a) sibling_function  - another function in the same file/module that
      handles the same resource WITHOUT the suspect pattern.
  (b) sibling_version   - a sibling protocol version directory or tagged
      file next to the vulnerable source path.
  (c) unaffected_asset  - a sibling token / asset / pool contract in the
      same directory that does not appear in the vulnerable path.
  (d) clean_config      - a deployment-config or fixture file alongside
      the vulnerable path that represents a safe configuration.

Proposals are clearly labeled ``candidate_unvalidated`` - the tool NEVER
asserts that a proposed control is confirmed.  Only an operator or a PoC
harness can confirm.

Schema id: auditooor.clean_control_finder.v1

Usage
-----
  python3 tools/clean-control-finder.py --workspace /path/to/ws [--json] [--strict]

  --json    Emit JSON report to stdout instead of human-readable text.
  --strict  Exit non-zero when any High/Critical row lacks all three fields
            AND no candidate control could be proposed.
"""
from __future__ import annotations

import argparse
import json
import re
import sys
from pathlib import Path
from typing import Any

SCHEMA = "auditooor.clean_control_finder.v1"
PROOF_BOUNDARY = (
    "Clean-control proposals are candidate_unvalidated. They are generated "
    "heuristically from source-ref paths and are never confirmed controls. "
    "An operator or PoC harness must validate each proposal before it can "
    "be cited as evidence in a report."
)

HIGH_PLUS_SEVERITIES = {"critical", "high"}

# Common config / fixture file name patterns (heuristic d)
CONFIG_PATTERNS = (
    re.compile(r"config", re.IGNORECASE),
    re.compile(r"fixture", re.IGNORECASE),
    re.compile(r"deploy", re.IGNORECASE),
    re.compile(r"setup", re.IGNORECASE),
    re.compile(r"params", re.IGNORECASE),
    re.compile(r"settings", re.IGNORECASE),
)

# Sibling version indicators (heuristic b)
VERSION_PATTERNS = (
    re.compile(r"v\d+", re.IGNORECASE),
    re.compile(r"V\d+"),
    re.compile(r"_v\d+", re.IGNORECASE),
    re.compile(r"@\d"),
)

MISSING_VALUES = {"", "unknown", "n/a", "na", "missing", "todo", "not_assessed", "none", "null"}


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _is_blank(value: Any) -> bool:
    if value is None:
        return True
    if isinstance(value, str) and value.strip().lower() in MISSING_VALUES:
        return True
    return False


def _read_json(path: Path) -> Any | None:
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except Exception:
        return None


def _load_exploit_queue(ws: Path) -> tuple[list[dict], str | None]:
    """Return (rows, error_message).  Never raises."""
    queue_path = ws / ".auditooor" / "exploit_queue.json"
    if not queue_path.exists():
        return [], f"missing_artifact: {queue_path}"
    data = _read_json(queue_path)
    if data is None:
        return [], f"unreadable_json: {queue_path}"
    if isinstance(data, list):
        return data, None
    if isinstance(data, dict):
        for key in ("rows", "queue", "items"):
            if key in data and isinstance(data[key], list):
                return data[key], None
        # dict with no recognised list key - treat as empty
        return [], f"unrecognised_queue_shape: keys={list(data.keys())[:8]}"
    return [], f"unexpected_queue_type: {type(data).__name__}"


def _source_refs_from_row(row: dict) -> list[str]:
    refs: list[str] = []
    for field in ("source_refs", "source_citations"):
        val = row.get(field)
        if isinstance(val, list):
            for item in val:
                if isinstance(item, str):
                    refs.append(item)
                elif isinstance(item, dict):
                    raw = item.get("raw") or item.get("path") or ""
                    if raw:
                        refs.append(raw)
    return refs


def _parse_file_path(ref: str, ws: Path) -> Path | None:
    """Extract a candidate filesystem path from a source-ref string."""
    # Strip line numbers like "path/foo.sol:123-456" or "path/foo.sol:123"
    clean = re.split(r":\d", ref)[0].strip()
    if not clean:
        return None
    candidate = ws / clean
    if candidate.exists():
        return candidate
    # Try as absolute path
    p = Path(clean)
    if p.is_absolute() and p.exists():
        return p
    return None


# ---------------------------------------------------------------------------
# Heuristic candidate proposers
# ---------------------------------------------------------------------------


def _heuristic_sibling_function(
    source_path: Path,
    row: dict,
    ws: Path,
) -> list[dict]:
    """Heuristic (a): sibling function in the same file."""
    candidates: list[dict] = []
    if not source_path.is_file():
        return candidates
    suffix = source_path.suffix.lower()
    # Only try for languages where we can pattern-match function defs
    if suffix not in (".sol", ".go", ".rs", ".py", ".ts", ".js"):
        return candidates
    try:
        text = source_path.read_text(encoding="utf-8", errors="replace")
    except Exception:
        return candidates

    # Extract function names depending on language
    if suffix == ".sol":
        names = re.findall(
            r"(?:function|modifier)\s+(\w+)\s*\(", text
        )
    elif suffix in (".go",):
        names = re.findall(r"^func\s+\(?[^)]*\)?\s*(\w+)\s*\(", text, re.MULTILINE)
    elif suffix == ".rs":
        names = re.findall(r"(?:pub\s+)?fn\s+(\w+)\s*[<\(]", text)
    else:
        names = re.findall(r"(?:function|def|func)\s+(\w+)\s*[\(\{]", text)

    names = list(dict.fromkeys(names))  # deduplicate preserving order
    if len(names) <= 1:
        return candidates

    # Identify likely "vulnerable" function from the row title or root cause
    suspect_hint = " ".join([
        str(row.get("title", "")),
        str(row.get("root_cause_hypothesis", "")),
        str(row.get("attack_class", "")),
    ]).lower()

    for fn in names:
        fn_lower = fn.lower()
        # Prefer sibling functions whose name does NOT appear in the suspect hint
        if fn_lower not in suspect_hint:
            candidates.append({
                "heuristic": "sibling_function",
                "candidate_unvalidated": True,
                "proposed_path": f"{source_path}::{fn}",
                "rationale": (
                    f"Sibling function '{fn}' in the same file "
                    f"({source_path.name}) may handle the same resource "
                    "without the suspect pattern."
                ),
            })
            if len(candidates) >= 3:
                break
    return candidates


def _heuristic_sibling_version(source_path: Path, ws: Path) -> list[dict]:
    """Heuristic (b): sibling protocol version in the same directory or parent.

    Checks two scopes:
    1. Siblings of the source_path itself (other files/dirs in same dir).
    2. If the source_path's parent directory has a version-like name (e.g. v2/),
       look at the grandparent for sibling version directories (e.g. v1/ next to v2/).
    """
    candidates: list[dict] = []
    if not source_path.exists():
        return candidates

    dirs_to_check: list[tuple[Path, Path]] = []  # (directory_to_scan, reference_item)

    if source_path.is_file():
        # scope 1: siblings in same directory
        dirs_to_check.append((source_path.parent, source_path))
        # scope 2: if parent dir is versioned, check grandparent for version siblings
        parent = source_path.parent
        if any(pat.search(parent.name) for pat in VERSION_PATTERNS):
            dirs_to_check.append((parent.parent, parent))
    else:
        dirs_to_check.append((source_path.parent, source_path))

    for scan_dir, reference in dirs_to_check:
        try:
            siblings = list(scan_dir.iterdir())
        except Exception:
            continue
        for sib in siblings:
            if sib == reference:
                continue
            if any(pat.search(sib.name) for pat in VERSION_PATTERNS):
                candidates.append({
                    "heuristic": "sibling_version",
                    "candidate_unvalidated": True,
                    "proposed_path": str(sib),
                    "rationale": (
                        f"'{sib.name}' appears to be a versioned sibling of "
                        f"'{reference.name}' and may represent a clean protocol "
                        "version without the vulnerability."
                    ),
                })
                if len(candidates) >= 2:
                    return candidates
    return candidates


def _heuristic_unaffected_asset(source_path: Path, ws: Path) -> list[dict]:
    """Heuristic (c): sibling asset/contract/token in the same directory."""
    candidates: list[dict] = []
    if not source_path.exists():
        return candidates
    parent = source_path.parent if source_path.is_file() else source_path
    target_suffix = source_path.suffix if source_path.is_file() else ""
    try:
        siblings = list(parent.iterdir())
    except Exception:
        return candidates

    for sib in siblings:
        if sib == source_path:
            continue
        if target_suffix and sib.suffix != target_suffix:
            continue
        if any(pat.search(sib.name) for pat in VERSION_PATTERNS):
            continue  # skip versioned siblings (handled by heuristic b)
        if any(pat.search(sib.name) for pat in CONFIG_PATTERNS):
            continue  # skip configs (handled by heuristic d)
        candidates.append({
            "heuristic": "unaffected_asset",
            "candidate_unvalidated": True,
            "proposed_path": str(sib),
            "rationale": (
                f"'{sib.name}' is a sibling asset/contract in the same "
                f"directory ({parent.name}/) and may be unaffected by the "
                "vulnerable pattern."
            ),
        })
        if len(candidates) >= 3:
            break
    return candidates


def _heuristic_clean_config(source_path: Path, ws: Path) -> list[dict]:
    """Heuristic (d): clean deployment config / fixture alongside the path."""
    candidates: list[dict] = []
    if not source_path.exists():
        return candidates
    parent = source_path.parent if source_path.is_file() else source_path
    try:
        siblings = list(parent.iterdir())
    except Exception:
        return candidates

    for sib in siblings:
        if sib == source_path:
            continue
        if any(pat.search(sib.name) for pat in CONFIG_PATTERNS):
            candidates.append({
                "heuristic": "clean_config",
                "candidate_unvalidated": True,
                "proposed_path": str(sib),
                "rationale": (
                    f"'{sib.name}' appears to be a deployment-config or "
                    "fixture file that may represent a safe configuration "
                    "against which the vulnerable path can be compared."
                ),
            })
            if len(candidates) >= 2:
                break
    return candidates


# ---------------------------------------------------------------------------
# Per-row analysis
# ---------------------------------------------------------------------------


def _analyse_row(row: dict, ws: Path) -> dict:
    """Analyse a single exploit-queue row and return a result dict."""
    lead_id = row.get("lead_id") or row.get("row_id") or "unknown"
    severity = str(row.get("likely_severity") or row.get("severity") or "").lower().strip()
    title = str(row.get("title") or "")
    proof_status = str(row.get("proof_status") or "")

    # Only High/Critical rows are in scope for C6
    in_scope = severity in HIGH_PLUS_SEVERITIES

    # Check existing field presence
    vpath = row.get("vulnerable_path")
    ctrl_path = row.get("clean_control_path")
    mat_diff = row.get("material_difference")

    has_vpath = not _is_blank(vpath)
    has_ctrl = not _is_blank(ctrl_path)
    has_diff = not _is_blank(mat_diff)
    all_three_present = has_vpath and has_ctrl and has_diff

    result: dict[str, Any] = {
        "lead_id": lead_id,
        "severity": severity,
        "title": title,
        "in_scope": in_scope,
        "proof_status": proof_status,
        "has_vulnerable_path": has_vpath,
        "has_clean_control_path": has_ctrl,
        "has_material_difference": has_diff,
        "all_three_present": all_three_present,
        "proposed_controls": [],
        "verdict": "ok" if all_three_present else ("out_of_scope" if not in_scope else "missing_fields"),
    }

    if not in_scope or all_three_present:
        return result

    # Collect candidate clean controls from source refs
    source_refs = _source_refs_from_row(row)
    proposals: list[dict] = []

    for ref in source_refs[:5]:  # process up to 5 refs to keep output bounded
        sp = _parse_file_path(ref, ws)
        if sp is None:
            continue
        # Run all four heuristics
        proposals.extend(_heuristic_sibling_function(sp, row, ws))
        proposals.extend(_heuristic_sibling_version(sp, ws))
        proposals.extend(_heuristic_unaffected_asset(sp, ws))
        proposals.extend(_heuristic_clean_config(sp, ws))

    # Deduplicate proposals by proposed_path
    seen: set[str] = set()
    unique: list[dict] = []
    for p in proposals:
        key = p.get("proposed_path", "")
        if key not in seen:
            seen.add(key)
            unique.append(p)

    result["proposed_controls"] = unique

    if unique:
        result["verdict"] = "missing_fields_with_proposals"
    else:
        result["verdict"] = "missing_fields_no_proposals"

    return result


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------


def run(ws_path: str, emit_json: bool, strict: bool) -> int:
    ws = Path(ws_path).resolve()
    rows, queue_error = _load_exploit_queue(ws)

    results: list[dict] = []
    missing_artifact = queue_error is not None

    if queue_error:
        results.append({
            "lead_id": "__queue__",
            "verdict": "missing_artifact",
            "message": queue_error,
            "in_scope": False,
        })
    else:
        for row in rows:
            results.append(_analyse_row(row, ws))

    # Summary statistics
    in_scope = [r for r in results if r.get("in_scope")]
    ok_count = sum(1 for r in in_scope if r.get("verdict") == "ok")
    missing_with_proposals = sum(
        1 for r in in_scope if r.get("verdict") == "missing_fields_with_proposals"
    )
    missing_no_proposals = sum(
        1 for r in in_scope if r.get("verdict") == "missing_fields_no_proposals"
    )

    report = {
        "schema_version": SCHEMA,
        "workspace": str(ws),
        "proof_boundary": PROOF_BOUNDARY,
        "summary": {
            "total_rows": len(rows),
            "in_scope_high_critical": len(in_scope),
            "ok_all_three_present": ok_count,
            "missing_fields_proposals_available": missing_with_proposals,
            "missing_fields_no_proposals": missing_no_proposals,
            "missing_artifact": missing_artifact,
        },
        "rows": results,
    }

    if emit_json:
        print(json.dumps(report, indent=2))
    else:
        _print_human(report)

    # Strict mode: exit non-zero when any in-scope row has missing fields and
    # no candidate control could be proposed.
    if strict and missing_no_proposals > 0:
        if not emit_json:
            print(
                f"\nSTRICT MODE FAIL: {missing_no_proposals} High/Critical row(s) "
                "lack all three required fields and no candidate controls were found.",
                file=sys.stderr,
            )
        return 1
    return 0


def _print_human(report: dict) -> None:
    s = report["summary"]
    print(f"clean-control-finder  workspace={report['workspace']}")
    print(f"  total_rows={s['total_rows']}  high/critical={s['in_scope_high_critical']}")
    print(f"  ok(all three present)={s['ok_all_three_present']}")
    print(f"  missing+proposals={s['missing_fields_proposals_available']}")
    print(f"  missing+no_proposals={s['missing_fields_no_proposals']}")
    if s.get("missing_artifact"):
        print("  WARNING: exploit queue not found - missing_artifact rows emitted")
    print()

    for row in report["rows"]:
        verdict = row.get("verdict", "?")
        lead_id = row.get("lead_id", "?")
        sev = row.get("severity", "?")
        if verdict == "missing_artifact":
            print(f"  [{lead_id}] MISSING_ARTIFACT: {row.get('message','')}")
            continue
        if verdict == "out_of_scope":
            continue  # skip non-high/critical in human mode
        if verdict == "ok":
            print(f"  [{lead_id}] OK  sev={sev}  all three fields present")
            continue
        print(
            f"  [{lead_id}] {verdict.upper()}  sev={sev}  "
            f"title={row.get('title','')[:60]}"
        )
        if not row.get("has_vulnerable_path"):
            print("    missing: vulnerable_path")
        if not row.get("has_clean_control_path"):
            print("    missing: clean_control_path")
        if not row.get("has_material_difference"):
            print("    missing: material_difference")
        proposals = row.get("proposed_controls", [])
        if proposals:
            print(f"    proposed controls ({len(proposals)}):")
            for p in proposals[:5]:
                heur = p.get("heuristic", "?")
                ppath = p.get("proposed_path", "?")
                print(f"      [{heur}] {ppath}")
                print(f"        rationale: {p.get('rationale','')}")
        print()


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description=(
            "C6 clean sibling/control finder - checks High/Critical exploit-queue rows "
            "for vulnerable_path, clean_control_path, and material_difference fields; "
            "proposes candidates when absent."
        )
    )
    parser.add_argument(
        "--workspace", "-w",
        required=True,
        metavar="PATH",
        help="Workspace root (the directory containing .auditooor/exploit_queue.json).",
    )
    parser.add_argument(
        "--json",
        dest="emit_json",
        action="store_true",
        default=False,
        help="Emit a JSON report instead of human-readable text.",
    )
    parser.add_argument(
        "--strict",
        action="store_true",
        default=False,
        help=(
            "Exit non-zero when any High/Critical row lacks all three required fields "
            "AND no candidate control could be proposed."
        ),
    )
    args = parser.parse_args(argv)
    return run(args.workspace, args.emit_json, args.strict)


if __name__ == "__main__":
    sys.exit(main())
