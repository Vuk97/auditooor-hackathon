#!/usr/bin/env python3
"""Resolve semantic fixture detector arguments to implemented detectors.

The semantic fixture smoke tools can infer a detector argument from a fixture
materialization manifest. This report makes that inference auditable: exact
detector ARGUMENT matches are the only rows that get smoke commands; everything
else remains terminal blocker evidence.
"""
from __future__ import annotations

import argparse
import json
import re
import shlex
from pathlib import Path
from typing import Any


SCHEMA_VERSION = "auditooor.semantic_detector_argument_resolver.v1"
ADVISORY_POSTURE = {
    "coverage_claim": "none_detector_argument_resolution_only",
    "evidence_class": "scaffolded_unverified",
    "advisory_only": True,
    "promotion_allowed": False,
    "severity": "none",
    "selected_impact": "",
    "submission_posture": "NOT_SUBMIT_READY",
    "impact_contract_required": True,
}


def _load_json(path: Path, label: str, *, required: bool = True) -> dict[str, Any]:
    if not path.is_file():
        if required:
            raise SystemExit(f"[semantic-detector-argument-resolver] missing {label}: {path}")
        return {}
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise SystemExit(f"[semantic-detector-argument-resolver] unreadable {label}: {path}: {exc}") from exc
    if not isinstance(payload, dict):
        raise SystemExit(f"[semantic-detector-argument-resolver] expected object JSON for {label}: {path}")
    return payload


def _write_json(path: Path, payload: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def _rel(workspace: Path, path: str) -> str:
    if not path:
        return ""
    try:
        return str(Path(path).resolve().relative_to(workspace.resolve()))
    except ValueError:
        return path


def _arg_value(parts: list[str], name: str) -> str:
    prefix = f"{name}="
    for idx, part in enumerate(parts):
        if part == name and idx + 1 < len(parts):
            return parts[idx + 1]
        if part.startswith(prefix):
            return part.split("=", 1)[1]
    return ""


def _slug_to_argument(value: str) -> str:
    return re.sub(r"[^a-z0-9]+", "-", value.lower()).strip("-")


def _pattern_name_from_source(source_component: str) -> str:
    name = Path(source_component).name
    return name[:-5] if name.endswith(".yaml") else Path(source_component).stem


def _parts_from_manifest(manifest: dict[str, Any]) -> list[str]:
    parts = [str(part) for part in (manifest.get("argv") or [])]
    if parts:
        return parts
    if not manifest.get("shell_command"):
        return []
    try:
        return shlex.split(str(manifest.get("shell_command") or ""))
    except ValueError:
        return []


def _infer_detector_argument(manifest: dict[str, Any]) -> dict[str, Any]:
    parts = _parts_from_manifest(manifest)
    pattern = _arg_value(parts, "--pattern")
    if pattern:
        return {"argument": pattern, "source": "manifest_argv_pattern", "confidence": "high"}
    source_pattern_path = str(manifest.get("source_pattern_path") or "")
    if source_pattern_path:
        return {
            "argument": _pattern_name_from_source(source_pattern_path),
            "source": "manifest_source_pattern_path",
            "confidence": "high",
        }
    source_component = str(manifest.get("source_component") or "")
    if source_component:
        return {
            "argument": _pattern_name_from_source(source_component),
            "source": "manifest_source_component",
            "confidence": "medium",
        }
    detector_slug = str(manifest.get("detector_slug") or "")
    if detector_slug:
        return {
            "argument": _slug_to_argument(detector_slug),
            "source": "manifest_detector_slug",
            "confidence": "medium",
        }
    return {"argument": "", "source": "unavailable", "confidence": "none"}


def _detector_index(workspace: Path) -> dict[str, list[str]]:
    index: dict[str, list[str]] = {}
    detectors_dir = workspace / "detectors"
    if not detectors_dir.is_dir():
        return index
    py_files = sorted(detectors_dir.glob("*.py")) + sorted(detectors_dir.glob("wave*/*.py"))
    for py_file in py_files:
        if py_file.name.startswith("_") or py_file.name == "run_custom.py":
            continue
        try:
            text = py_file.read_text(encoding="utf-8", errors="ignore")
        except OSError:
            continue
        for argument in re.findall(r"\bARGUMENT\s*=\s*['\"]([^'\"]+)['\"]", text):
            index.setdefault(argument, []).append(str(py_file.resolve()))
    return index


def _pattern_index(workspace: Path) -> dict[str, list[str]]:
    roots = [
        workspace / "reference" / "patterns.dsl",
        workspace / "detectors" / "_specs" / "drafts_solodit",
    ]
    index: dict[str, list[str]] = {}
    for root in roots:
        if not root.is_dir():
            continue
        for path in sorted(root.glob("*.yaml")):
            index.setdefault(path.stem, []).append(str(path.resolve()))
    return index


def _read_manifest(path: str) -> dict[str, Any]:
    if not path:
        return {}
    try:
        payload = json.loads(Path(path).read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return {}
    return payload if isinstance(payload, dict) else {}


def _rows_from_tasks(workspace: Path, tasks_path: Path, limit: int) -> list[dict[str, Any]]:
    tasks = _load_json(tasks_path, "semantic fixture smoke tasks")
    rows = [row for row in (tasks.get("rows") or []) if isinstance(row, dict)]
    out: list[dict[str, Any]] = []
    for row in rows[:limit]:
        manifest_path = str(row.get("fixture_manifest_path") or "")
        manifest = _read_manifest(manifest_path)
        preflight = row.get("dependency_preflight") if isinstance(row.get("dependency_preflight"), dict) else {}
        detector_inference = (
            preflight.get("detector_argument_inference")
            if isinstance(preflight.get("detector_argument_inference"), dict)
            else {}
        )
        inference = detector_inference.get("inference") if isinstance(detector_inference.get("inference"), dict) else {}
        if not inference:
            inference = _infer_detector_argument(manifest)
        out.append({
            "queue_id": row.get("queue_id", ""),
            "inventory_id": row.get("inventory_id", ""),
            "terminal_state": row.get("terminal_state", ""),
            "source_component": row.get("source_component", ""),
            "suggested_detector_slug": row.get("suggested_detector_slug", ""),
            "candidate_detector_family": row.get("candidate_detector_family", ""),
            "positive_fixture_path": row.get("positive_fixture_path", ""),
            "clean_fixture_path": row.get("clean_fixture_path", ""),
            "smoke_record_path": row.get("smoke_record_path", ""),
            "fixture_manifest_path": manifest_path,
            "fixture_manifest": manifest,
            "inference": inference,
        })
    return out


def _smoke_command(workspace: Path, argument: str, positive: str, clean: str) -> dict[str, str]:
    positive_rel = _rel(workspace, positive)
    clean_rel = _rel(workspace, clean)
    return {
        "positive": " ".join(shlex.quote(part) for part in [
            "python3",
            "detectors/run_custom.py",
            positive_rel,
            argument,
        ]),
        "clean": " ".join(shlex.quote(part) for part in [
            "python3",
            "detectors/run_custom.py",
            clean_rel,
            argument,
        ]),
    }


def _generated_fixture_pair(workspace: Path, argument: str) -> dict[str, str]:
    slug = argument.replace("-", "_")
    positive = workspace / "detectors" / "test_fixtures" / f"{slug}_vulnerable.sol"
    clean = workspace / "detectors" / "test_fixtures" / f"{slug}_clean.sol"
    if positive.is_file() and clean.is_file():
        return {"positive": str(positive), "clean": str(clean)}
    return {}


def _resolve_row(
    workspace: Path,
    row: dict[str, Any],
    detector_idx: dict[str, list[str]],
    pattern_idx: dict[str, list[str]],
) -> dict[str, Any]:
    inference = row.get("inference") if isinstance(row.get("inference"), dict) else {}
    argument = str(inference.get("argument") or "")
    detector_paths = detector_idx.get(argument, [])
    pattern_paths = pattern_idx.get(argument, [])
    terminal_state = str(row.get("terminal_state") or "")
    positive = str(row.get("positive_fixture_path") or "")
    clean = str(row.get("clean_fixture_path") or "")
    positive_exists = bool(positive and Path(positive).is_file())
    clean_exists = bool(clean and Path(clean).is_file())
    fixture_pair_source = "semantic_fixture_pair" if positive_exists and clean_exists else ""
    generated_pair = _generated_fixture_pair(workspace, argument) if argument else {}
    smoke_positive = positive
    smoke_clean = clean
    if not fixture_pair_source and generated_pair:
        smoke_positive = generated_pair["positive"]
        smoke_clean = generated_pair["clean"]
        fixture_pair_source = "generated_detector_fixture_pair"

    if terminal_state == "terminal_extraction_failed":
        resolution = "terminal_extraction_failed_detector_argument_unresolved"
        blockers = [
            "fixture extraction failed before detector smoke could be wired",
            "do not synthesize detector proof from inferred argument",
        ]
    elif not argument:
        resolution = "terminal_missing_detector_argument"
        blockers = ["no detector argument could be inferred safely"]
    elif detector_paths and fixture_pair_source:
        resolution = "smoke_execution_wired_existing_detector"
        blockers = []
    elif detector_paths:
        resolution = "terminal_existing_detector_missing_fixture_pair"
        blockers = ["existing detector ARGUMENT matched, but vulnerable/clean fixture files are not both present"]
    elif pattern_paths:
        resolution = "terminal_pattern_without_detector_implementation"
        blockers = ["matching pattern YAML exists, but no detector ARGUMENT implementation exists for run_custom.py"]
    else:
        resolution = "terminal_missing_detector_implementation"
        blockers = ["no exact detector ARGUMENT implementation matched the inferred argument"]

    smoke_commands = (
        _smoke_command(workspace, argument, smoke_positive, smoke_clean)
        if resolution == "smoke_execution_wired_existing_detector"
        else {}
    )
    return {
        "queue_id": row.get("queue_id", ""),
        "inventory_id": row.get("inventory_id", ""),
        "argument": argument,
        "inference": inference,
        "resolution": resolution,
        "source_component": row.get("source_component", ""),
        "suggested_detector_slug": row.get("suggested_detector_slug", ""),
        "candidate_detector_family": row.get("candidate_detector_family", ""),
        "terminal_state": terminal_state,
        "detector_paths": [_rel(workspace, path) for path in detector_paths],
        "pattern_paths": [_rel(workspace, path) for path in pattern_paths],
        "positive_fixture_path": _rel(workspace, positive),
        "clean_fixture_path": _rel(workspace, clean),
        "smoke_positive_fixture_path": _rel(workspace, smoke_positive),
        "smoke_clean_fixture_path": _rel(workspace, smoke_clean),
        "fixture_pair_source": fixture_pair_source,
        "smoke_record_path": _rel(workspace, str(row.get("smoke_record_path") or "")),
        "fixture_manifest_path": _rel(workspace, str(row.get("fixture_manifest_path") or "")),
        "positive_fixture_exists": positive_exists,
        "clean_fixture_exists": clean_exists,
        "smoke_positive_fixture_exists": bool(smoke_positive and Path(smoke_positive).is_file()),
        "smoke_clean_fixture_exists": bool(smoke_clean and Path(smoke_clean).is_file()),
        "smoke_commands": smoke_commands,
        "blockers": blockers,
        "terminal_blocker": resolution.startswith("terminal_"),
        **ADVISORY_POSTURE,
    }


def _markdown(payload: dict[str, Any]) -> str:
    lines = [
        "# Semantic Detector Argument Resolver",
        "",
        f"- Workspace: `{payload['workspace']}`",
        f"- Processed rows: {payload['processed_count']} / source rows {payload['source_row_count']}",
        f"- Exact detector matches with smoke commands: {payload['smoke_execution_wired_count']}",
        f"- Terminal detector argument blockers: {payload['terminal_detector_argument_blocker_count']}",
        f"- Extraction-failed terminal rows: {payload['terminal_extraction_failed_count']}",
        f"- Promotion allowed: `{payload['promotion_allowed']}`",
        "",
        "## Resolution Counts",
    ]
    for key, value in sorted(payload["resolution_counts"].items()):
        lines.append(f"- `{key}`: {value}")
    lines.extend(["", "## Rows"])
    for row in payload["rows"]:
        lines.append(
            f"- `{row['queue_id']}` `{row['argument'] or '<missing>'}`: "
            f"{row['resolution']} ({'; '.join(row['blockers']) or 'smoke command ready'})"
        )
    lines.append("")
    return "\n".join(lines)


def build_report(workspace: Path, *, tasks_path: Path, limit: int) -> dict[str, Any]:
    source_rows = _rows_from_tasks(workspace, tasks_path, limit)
    detector_idx = _detector_index(workspace)
    pattern_idx = _pattern_index(workspace)
    rows = [_resolve_row(workspace, row, detector_idx, pattern_idx) for row in source_rows]
    resolution_counts: dict[str, int] = {}
    for row in rows:
        resolution = str(row["resolution"])
        resolution_counts[resolution] = resolution_counts.get(resolution, 0) + 1
    terminal_detector_argument_blocker_count = sum(
        1
        for row in rows
        if row["terminal_blocker"] and row["resolution"] != "terminal_extraction_failed_detector_argument_unresolved"
    )
    return {
        "schema": SCHEMA_VERSION,
        "workspace": str(workspace),
        "source_artifacts": {
            "semantic_fixture_smoke_tasks": str(tasks_path),
        },
        "limit": limit,
        "source_row_count": len(source_rows),
        "processed_count": len(rows),
        "implemented_detector_argument_count": len(detector_idx),
        "pattern_argument_count": len(pattern_idx),
        "smoke_execution_wired_count": resolution_counts.get("smoke_execution_wired_existing_detector", 0),
        "terminal_detector_argument_blocker_count": terminal_detector_argument_blocker_count,
        "terminal_extraction_failed_count": resolution_counts.get(
            "terminal_extraction_failed_detector_argument_unresolved",
            0,
        ),
        "resolution_counts": resolution_counts,
        "rows": rows,
        "next_actions": [
            "Run only rows with resolution=smoke_execution_wired_existing_detector; all other rows are terminal blockers.",
            "Do not create detector proof from a matching pattern YAML unless a detector ARGUMENT implementation exists.",
            "For terminal_missing_detector_implementation rows, implement detector plus vulnerable/clean fixture pair before smoke.",
        ],
        **ADVISORY_POSTURE,
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--workspace", required=True, type=Path)
    parser.add_argument("--tasks", type=Path, help="semantic_fixture_smoke_tasks.json path")
    parser.add_argument("--limit", type=int, default=500)
    parser.add_argument("--out-json", type=Path)
    parser.add_argument("--out-md", type=Path)
    parser.add_argument("--print-json", action="store_true")
    args = parser.parse_args()

    workspace = args.workspace.expanduser().resolve()
    tasks_path = (args.tasks or workspace / ".auditooor" / "semantic_fixture_smoke_tasks.json").expanduser().resolve()
    out_json = (args.out_json or workspace / ".auditooor" / "semantic_detector_argument_resolver.json").expanduser().resolve()
    out_md = (args.out_md or workspace / ".auditooor" / "semantic_detector_argument_resolver.md").expanduser().resolve()

    payload = build_report(workspace, tasks_path=tasks_path, limit=args.limit)
    _write_json(out_json, payload)
    out_md.parent.mkdir(parents=True, exist_ok=True)
    out_md.write_text(_markdown(payload), encoding="utf-8")
    if args.print_json:
        print(json.dumps(payload, indent=2, sort_keys=True))
    else:
        print(
            "[semantic-detector-argument-resolver] "
            f"processed={payload['processed_count']} "
            f"smoke_wired={payload['smoke_execution_wired_count']} "
            f"terminal_blockers={payload['terminal_detector_argument_blocker_count']} "
            f"extraction_failed={payload['terminal_extraction_failed_count']}"
        )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
