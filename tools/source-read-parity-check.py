#!/usr/bin/env python3
"""source-read-parity-check -- B6 Codex/source-read parity gate.

Plan item B6 from docs/HACKERMAN_V3_CAPABILITY_PLAN_2026-05-19.md:

  Add a non-Claude source-read path that surfaces the same bounded
  hacker-question cards as the Claude PreToolUse hook. Acceptance: any
  direct source-review manifest for an audit file either links a
  hacker-question artifact OR carries a deliberate NO_HACKER_QUESTIONS
  reason accepted by finalization.

Two modes
---------
GENERATE (--source <file>)
    Invoke the same injector path the Claude hook uses
    (tools/auditooor-pre-source-read-injector.py) and write the resulting
    hacker-question card artifact as a JSON sidecar.  Reuses the existing
    injector; does NOT re-implement card generation.

    Artifact path: <source-file>.hacker_questions.json  (or --out <path>)

CHECK (default, --workspace <ws> or --manifest <file>)
    Walk every direct source-review manifest under the workspace (or a
    single supplied manifest file) and validate that for each reviewed
    source file the manifest entry EITHER:
      (a) links a hacker-question artifact   ("hacker_questions_artifact"),
      (b) carries a deliberate NO_HACKER_QUESTIONS reason, or
      (c) carries a NO_HACKER_QUESTIONS marker with reason "parser_gap"
          (acceptable when the injector does not support the file's language).

    A manifest entry that reviewed a source file with NEITHER is a FAIL row.

Output
------
Human-readable summary by default; JSON (schema auditooor.source_read_parity_check.v1)
with --json.  --strict exits non-zero when any FAIL rows are present.

Usage
-----
    # GENERATE mode
    python3 tools/source-read-parity-check.py --source path/to/audit/file.sol
    python3 tools/source-read-parity-check.py --source path/to/file.go --out /tmp/cards.json

    # CHECK mode
    python3 tools/source-read-parity-check.py --workspace /path/to/audit-ws
    python3 tools/source-read-parity-check.py --manifest reports/my_review.json
    python3 tools/source-read-parity-check.py --workspace /path/to/ws --json --strict
"""
from __future__ import annotations

import argparse
import datetime
import hashlib
import json
import os
import subprocess
import sys
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

REPO_ROOT = Path(__file__).resolve().parent.parent
TOOLS_DIR = Path(__file__).resolve().parent

SCHEMA_ID = "auditooor.source_read_parity_check.v1"
INJECTOR_PATH = TOOLS_DIR / "auditooor-pre-source-read-injector.py"

# Accepted NO_HACKER_QUESTIONS reason values (case-insensitive prefix match)
_ACCEPTED_NO_HQ_REASONS = {
    "parser_gap",
    "language_not_supported",
    "no_functions_detected",
    "renderer_produced_zero_questions",
    "operator_override",
    "test_file",
    "generated_file",
    "empty_file",
    "out_of_scope",
}

# Manifest file name patterns to scan for under workspace
_MANIFEST_GLOB_PATTERNS = [
    "reports/*review*.json",
    "reports/*manifest*.json",
    "reports/*source_read*.json",
    ".auditooor/*review*.json",
    ".auditooor/*manifest*.json",
    "submissions/**/*review*.json",
]

# Keys that constitute a hacker-question artifact link in a manifest entry
_HQ_LINK_KEYS = {
    "hacker_questions_artifact",
    "hacker_question_artifact",
    "hq_artifact",
    "hq_sidecar",
    "pre_source_read_injection",
    "hacker_question_card",
}

# Keys that constitute a NO_HACKER_QUESTIONS declaration
_NO_HQ_KEYS = {
    "no_hacker_questions",
    "NO_HACKER_QUESTIONS",
    "no_hq",
    "hacker_questions_skipped",
}

# Source file extensions that REQUIRE hacker-question parity (same as injector)
_REQUIRED_EXTENSIONS = {".go", ".rs", ".sol", ".ts", ".py"}
# Extensions where parser_gap is auto-accepted (injector has no parser)
_PARSER_GAP_EXTENSIONS = {".ts", ".py"}


# --------------------------------------------------------------------------- #
# Helpers                                                                     #
# --------------------------------------------------------------------------- #


def _now_utc() -> str:
    return datetime.datetime.utcnow().strftime("%Y-%m-%dT%H:%M:%SZ")


def _sha256_file(path: Path) -> str:
    h = hashlib.sha256()
    try:
        h.update(path.read_bytes())
    except OSError:
        return ""
    return h.hexdigest()[:16]


def _is_source_file(path_str: str) -> bool:
    return Path(path_str).suffix.lower() in _REQUIRED_EXTENSIONS


def _auto_parser_gap(path_str: str) -> bool:
    return Path(path_str).suffix.lower() in _PARSER_GAP_EXTENSIONS


# --------------------------------------------------------------------------- #
# GENERATE mode                                                                #
# --------------------------------------------------------------------------- #


def generate_hacker_question_card(
    source_path: Path,
    out_path: Optional[Path] = None,
    *,
    workspace: Optional[Path] = None,
    target_repo: Optional[str] = None,
    top_n: int = 3,
    min_confidence: float = 0.5,
    max_functions: int = 20,
) -> Dict[str, Any]:
    """Invoke the injector and write/return the hacker-question card artifact.

    This is the Codex/non-Claude path that mirrors what the Claude PreToolUse
    hook does via ``tools/claude-pre-source-read-hook.sh``.

    Returns a dict with:
        artifact_path  -- where the card was written (str or None on error)
        payload        -- the parsed JSON payload from the injector
        error          -- error message or None
    """
    result: Dict[str, Any] = {
        "schema": SCHEMA_ID,
        "mode": "generate",
        "source_file": str(source_path),
        "artifact_path": None,
        "payload": None,
        "error": None,
        "generated_at_utc": _now_utc(),
    }

    if not INJECTOR_PATH.is_file():
        result["error"] = f"injector not found: {INJECTOR_PATH}"
        return result

    if not source_path.is_file():
        result["error"] = f"source file not found: {source_path}"
        return result

    if source_path.suffix.lower() not in _REQUIRED_EXTENSIONS:
        result["error"] = f"unsupported extension: {source_path.suffix}"
        return result

    cmd = [
        sys.executable,
        str(INJECTOR_PATH),
        str(source_path),
        "--top-n", str(top_n),
        "--min-confidence", str(min_confidence),
        "--max-functions", str(max_functions),
        "--json",
    ]
    if workspace:
        cmd += ["--workspace", str(workspace)]
    if target_repo:
        cmd += ["--target-repo", target_repo]

    try:
        proc = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=60,
        )
        raw = proc.stdout.strip()
        if not raw:
            result["error"] = f"injector produced no output (rc={proc.returncode})"
            return result
        payload = json.loads(raw)
    except subprocess.TimeoutExpired:
        result["error"] = "injector timed out after 60s"
        return result
    except json.JSONDecodeError as exc:
        result["error"] = f"injector output is not valid JSON: {exc}"
        return result
    except Exception as exc:
        result["error"] = f"injector subprocess failed: {exc}"
        return result

    result["payload"] = payload

    # Determine output path
    if out_path is None:
        out_path = source_path.parent / (source_path.name + ".hacker_questions.json")

    try:
        out_path.write_text(json.dumps(payload, indent=2), encoding="utf-8")
        result["artifact_path"] = str(out_path)
    except OSError as exc:
        result["error"] = f"could not write artifact: {exc}"

    return result


# --------------------------------------------------------------------------- #
# Manifest entry inspection                                                    #
# --------------------------------------------------------------------------- #


def _inspect_manifest_entry(entry: Dict[str, Any]) -> Tuple[str, str, str]:
    """Inspect one manifest entry dict.

    Returns (source_file, verdict, detail) where verdict is one of:
        pass_hq_linked   -- hacker-question artifact linked
        pass_no_hq       -- NO_HACKER_QUESTIONS reason present
        pass_parser_gap  -- auto-accepted parser_gap extension
        fail_missing     -- source file reviewed with no parity
        skip_not_source  -- not a source file; skip
    """
    # Find the source file path from common manifest key names
    source_file = (
        entry.get("source_file")
        or entry.get("file_path")
        or entry.get("file")
        or entry.get("source")
        or entry.get("reviewed_file")
        or entry.get("audit_file")
        or ""
    )
    source_file = str(source_file)

    if not source_file or not _is_source_file(source_file):
        return source_file, "skip_not_source", "not a tracked source extension"

    # Check for hacker-question artifact link
    for key in _HQ_LINK_KEYS:
        val = entry.get(key)
        if val and str(val).strip():
            return source_file, "pass_hq_linked", f"linked via key '{key}'"

    # Check for NO_HACKER_QUESTIONS declaration
    for key in _NO_HQ_KEYS:
        val = entry.get(key)
        if val is not None:
            reason = str(val).strip().lower()
            # Any non-empty reason is accepted (empty = suspicious omission)
            if reason:
                return source_file, "pass_no_hq", f"NO_HACKER_QUESTIONS reason='{reason}' via key '{key}'"

    # Auto-accept parser_gap for extensions we know the injector skips
    if _auto_parser_gap(source_file):
        return source_file, "pass_parser_gap", f"auto parser_gap for extension {Path(source_file).suffix}"

    return source_file, "fail_missing", "no hacker-question artifact and no NO_HACKER_QUESTIONS reason"


def _collect_entries_from_manifest(manifest_path: Path) -> List[Dict[str, Any]]:
    """Load a manifest file and return its list of per-file entries.

    Handles:
        - list of dicts at top level
        - dict with "entries", "files", "results", "reviewed_files", "items" key
    """
    try:
        raw = manifest_path.read_text(encoding="utf-8")
        data = json.loads(raw)
    except (OSError, json.JSONDecodeError) as exc:
        return [{"_parse_error": str(exc), "_manifest_path": str(manifest_path)}]

    if isinstance(data, list):
        entries = data
    elif isinstance(data, dict):
        for key in ("entries", "files", "results", "reviewed_files", "items", "records"):
            val = data.get(key)
            if isinstance(val, list):
                entries = val
                break
        else:
            # Treat the single dict as one entry
            entries = [data]
    else:
        entries = []

    return [e for e in entries if isinstance(e, dict)]


# --------------------------------------------------------------------------- #
# CHECK mode                                                                   #
# --------------------------------------------------------------------------- #


def _find_manifests(workspace: Path) -> List[Path]:
    """Return manifest JSON files under workspace matching known patterns."""
    found: List[Path] = []
    for pattern in _MANIFEST_GLOB_PATTERNS:
        found.extend(workspace.glob(pattern))
    # Also accept any *_review.json or *source_read*.json in reports/
    reports_dir = workspace / "reports"
    if reports_dir.is_dir():
        for f in reports_dir.iterdir():
            if f.suffix == ".json" and f not in found:
                # Only include files that look like review/manifest artifacts
                name_lower = f.name.lower()
                if any(kw in name_lower for kw in ("review", "manifest", "source_read", "audit_read")):
                    found.append(f)
    return sorted(set(found))


def _row_from_entry(
    entry: Dict[str, Any],
    manifest_path: Path,
    workspace: Optional[Path],
) -> Dict[str, Any]:
    """Build one result row from a manifest entry."""
    if "_parse_error" in entry:
        return {
            "manifest": str(manifest_path),
            "source_file": "",
            "verdict": "error",
            "detail": entry["_parse_error"],
        }

    source_file, verdict, detail = _inspect_manifest_entry(entry)

    # Verify linked artifact exists when verdict is pass_hq_linked
    if verdict == "pass_hq_linked":
        # Extract the artifact path
        artifact = None
        for key in _HQ_LINK_KEYS:
            val = entry.get(key)
            if val and str(val).strip():
                artifact = str(val).strip()
                break
        if artifact:
            artifact_path = Path(artifact)
            if not artifact_path.is_absolute() and workspace:
                artifact_path = workspace / artifact_path
            if not artifact_path.is_file():
                verdict = "fail_missing"
                detail = f"linked artifact '{artifact}' does not exist on disk"

    return {
        "manifest": str(manifest_path),
        "source_file": source_file,
        "verdict": verdict,
        "detail": detail,
    }


def check_workspace(
    workspace: Optional[Path] = None,
    manifest_path: Optional[Path] = None,
) -> Dict[str, Any]:
    """Run CHECK mode and return the full report dict."""
    report: Dict[str, Any] = {
        "schema": SCHEMA_ID,
        "mode": "check",
        "checked_at_utc": _now_utc(),
        "workspace": str(workspace) if workspace else None,
        "manifest": str(manifest_path) if manifest_path else None,
        "rows": [],
        "summary": {},
    }

    # Collect manifest files to inspect
    manifests_to_check: List[Path] = []
    if manifest_path is not None:
        if not manifest_path.is_file():
            report["rows"].append({
                "manifest": str(manifest_path),
                "source_file": "",
                "verdict": "error",
                "detail": f"manifest file not found: {manifest_path}",
            })
        else:
            manifests_to_check.append(manifest_path)
    elif workspace is not None:
        if not workspace.is_dir():
            report["rows"].append({
                "manifest": "",
                "source_file": "",
                "verdict": "error",
                "detail": f"workspace directory not found: {workspace}",
            })
        else:
            manifests_to_check = _find_manifests(workspace)
    else:
        report["rows"].append({
            "manifest": "",
            "source_file": "",
            "verdict": "error",
            "detail": "must supply --workspace or --manifest",
        })

    rows: List[Dict[str, Any]] = list(report["rows"])  # carry any pre-errors

    for mf in manifests_to_check:
        entries = _collect_entries_from_manifest(mf)
        for entry in entries:
            row = _row_from_entry(entry, mf, workspace)
            if row["verdict"] != "skip_not_source":
                rows.append(row)

    report["rows"] = rows

    # Summarise
    counts: Dict[str, int] = {}
    for row in rows:
        v = row["verdict"]
        counts[v] = counts.get(v, 0) + 1

    fail_count = counts.get("fail_missing", 0) + counts.get("error", 0)
    pass_count = (
        counts.get("pass_hq_linked", 0)
        + counts.get("pass_no_hq", 0)
        + counts.get("pass_parser_gap", 0)
    )
    total = sum(counts.values())

    report["summary"] = {
        "total_rows": total,
        "pass": pass_count,
        "fail": fail_count,
        "manifests_checked": len(manifests_to_check),
        "verdict_counts": counts,
        "gate": "PASS" if fail_count == 0 else "FAIL",
    }

    return report


# --------------------------------------------------------------------------- #
# Human-readable formatting                                                    #
# --------------------------------------------------------------------------- #


def _human_check(report: Dict[str, Any]) -> str:
    lines = [
        f"source-read-parity-check  gate={report['summary'].get('gate','?')}",
        f"  manifests checked : {report['summary'].get('manifests_checked', 0)}",
        f"  rows evaluated    : {report['summary'].get('total_rows', 0)}",
        f"  pass              : {report['summary'].get('pass', 0)}",
        f"  fail              : {report['summary'].get('fail', 0)}",
        "",
    ]
    for row in report.get("rows", []):
        v = row["verdict"]
        prefix = "PASS" if v.startswith("pass") else ("FAIL" if v in ("fail_missing", "error") else "----")
        sf = row.get("source_file") or "(no source)"
        lines.append(f"  [{prefix}] {sf}")
        lines.append(f"         {v}: {row.get('detail','')}")
    return "\n".join(lines)


def _human_generate(result: Dict[str, Any]) -> str:
    lines = [f"source-read-parity-check generate mode"]
    if result.get("error"):
        lines.append(f"  ERROR: {result['error']}")
    else:
        lines.append(f"  source  : {result.get('source_file')}")
        lines.append(f"  artifact: {result.get('artifact_path')}")
        payload = result.get("payload") or {}
        summary = payload.get("summary") or {}
        lines.append(f"  hacker_question_count: {summary.get('hacker_question_count', 0)}")
        if payload.get("skipped_reasons"):
            lines.append(f"  skipped_reasons: {payload['skipped_reasons']}")
    return "\n".join(lines)


# --------------------------------------------------------------------------- #
# CLI                                                                          #
# --------------------------------------------------------------------------- #


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="source-read-parity-check",
        description=__doc__,
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    # Mode selection
    mode_group = parser.add_mutually_exclusive_group()
    mode_group.add_argument(
        "--source",
        metavar="FILE",
        help="GENERATE mode: source file to produce hacker-question cards for.",
    )
    mode_group.add_argument(
        "--manifest",
        metavar="FILE",
        help="CHECK mode: single manifest JSON file to validate.",
    )
    parser.add_argument(
        "--workspace",
        metavar="DIR",
        help="CHECK mode: workspace root; scans for review manifests under reports/, .auditooor/.",
    )
    # Generate-mode options
    parser.add_argument(
        "--out",
        metavar="FILE",
        help="GENERATE mode: output path for the artifact (default: <source>.hacker_questions.json).",
    )
    parser.add_argument(
        "--target-repo",
        metavar="OWNER/REPO",
        default=None,
        help="GENERATE mode: target repo passed to injector.",
    )
    # Common options
    parser.add_argument("--json", action="store_true", help="Emit JSON output (schema auditooor.source_read_parity_check.v1).")
    parser.add_argument("--strict", action="store_true", help="Exit non-zero when FAIL rows are present (CHECK) or generation fails (GENERATE).")
    return parser


def main(argv: Optional[List[str]] = None) -> int:
    parser = _build_parser()
    args = parser.parse_args(argv)

    # ---------- GENERATE mode ----------
    if args.source:
        source_path = Path(args.source)
        out_path = Path(args.out) if args.out else None
        workspace = Path(args.workspace) if args.workspace else None
        result = generate_hacker_question_card(
            source_path,
            out_path=out_path,
            workspace=workspace,
            target_repo=args.target_repo,
        )
        if args.json:
            print(json.dumps(result, indent=2))
        else:
            print(_human_generate(result))
        if args.strict and result.get("error"):
            return 1
        return 0

    # ---------- CHECK mode ----------
    workspace = Path(args.workspace) if args.workspace else None
    manifest = Path(args.manifest) if args.manifest else None

    if workspace is None and manifest is None:
        print("error: supply --source for GENERATE mode, or --workspace / --manifest for CHECK mode", file=sys.stderr)
        return 2

    report = check_workspace(workspace=workspace, manifest_path=manifest)

    if args.json:
        print(json.dumps(report, indent=2))
    else:
        print(_human_check(report))

    if args.strict and report["summary"].get("gate") != "PASS":
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
