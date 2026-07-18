#!/usr/bin/env python3
"""cross-lane-correlate.py — join typed deep candidates by cited files.

This is the cheap/default-on V5 G2 bridge between deep lanes. Every lane that
emits ``deep_candidate.v1`` already records the files that support the claim;
this tool groups candidates that cite the same file across two or more lanes so
operators can spot "math + fuzz + source-mining all point here" clusters.
"""
from __future__ import annotations

import argparse
import json
import sys
from collections import defaultdict
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional, Sequence


SCHEMA_VERSION = "auditooor.cross_lane_correlations.v1"
VALID_SCHEMA = "deep_candidate.v1"


def _read_json(path: Path) -> Dict[str, Any]:
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except json.JSONDecodeError as exc:
        raise ValueError(f"{path}: invalid JSON: {exc}") from exc
    if not isinstance(data, dict):
        raise ValueError(f"{path}: expected a JSON object")
    return data


def _norm_file(value: object) -> Optional[str]:
    if not isinstance(value, str):
        return None
    text = value.strip().replace("\\", "/")
    if not text:
        return None
    # Strip line/column suffixes while preserving Windows drive letters poorly
    # but safely enough for repo/workspace-relative Solidity paths.
    parts = text.rsplit(":", 2)
    if len(parts) > 1 and all(p.isdigit() for p in parts[1:]):
        text = parts[0]
    elif len(parts) > 1 and parts[-1].isdigit():
        text = ":".join(parts[:-1])
    return text.lstrip("./")


def load_candidates(workspace: Path) -> List[Dict[str, Any]]:
    root = workspace / "deep_candidates"
    if not root.is_dir():
        return []
    out: List[Dict[str, Any]] = []
    for path in sorted(root.rglob("*.json"), key=lambda p: str(p)):
        doc = _read_json(path)
        if doc.get("schema_version") != VALID_SCHEMA:
            continue
        files = [_norm_file(item) for item in (doc.get("files") or [])]
        files = [item for item in files if item]
        if not files:
            continue
        out.append({
            "candidate_id": doc.get("candidate_id") or path.stem,
            "lane": doc.get("lane") or "unknown",
            "confidence": doc.get("confidence"),
            "promotion_status": doc.get("promotion_status"),
            "files": sorted(set(files)),
            "path": str(path.relative_to(workspace)),
        })
    return out


def correlate(candidates: Sequence[Dict[str, Any]]) -> List[Dict[str, Any]]:
    by_file: Dict[str, List[Dict[str, Any]]] = defaultdict(list)
    for cand in candidates:
        for file_name in cand.get("files") or []:
            by_file[str(file_name)].append(cand)

    out: List[Dict[str, Any]] = []
    for file_name, group in sorted(by_file.items()):
        lanes = sorted({str(c.get("lane") or "unknown") for c in group})
        if len(lanes) < 2 or len(group) < 2:
            continue
        out.append({
            "file": file_name,
            "lanes": lanes,
            "candidate_count": len(group),
            "candidates": [
                {
                    "candidate_id": str(c.get("candidate_id") or "unknown"),
                    "lane": str(c.get("lane") or "unknown"),
                    "confidence": c.get("confidence"),
                    "promotion_status": c.get("promotion_status"),
                    "path": c.get("path"),
                }
                for c in sorted(
                    group,
                    key=lambda item: (
                        str(item.get("lane") or ""),
                        str(item.get("candidate_id") or ""),
                        str(item.get("path") or ""),
                    ),
                )
            ],
        })
    return out


def build_payload(workspace: Path) -> Dict[str, Any]:
    candidates = load_candidates(workspace)
    correlations = correlate(candidates)
    return {
        "schema_version": SCHEMA_VERSION,
        "generated_at": "not-recorded-for-idempotence",
        "workspace": str(workspace),
        "candidate_count": len(candidates),
        "correlation_count": len(correlations),
        "correlations": correlations,
    }


def render_markdown(payload: Dict[str, Any]) -> str:
    lines = [
        "# Cross-Lane Candidate Correlations",
        "",
        "Schema: `auditooor.cross_lane_correlations.v1`",
        "",
        f"- candidates scanned: {payload.get('candidate_count', 0)}",
        f"- correlations: {payload.get('correlation_count', 0)}",
        "",
    ]
    correlations = payload.get("correlations") or []
    if not correlations:
        lines.extend([
            "No cross-lane file-overlap correlations found.",
            "",
        ])
        return "\n".join(lines)
    lines.extend([
        "| file | lanes | candidate_count | candidates |",
        "|---|---|---:|---|",
    ])
    for item in correlations:
        candidates = ", ".join(
            f"{c.get('lane')}:{c.get('candidate_id')}"
            for c in item.get("candidates", [])
        )
        lines.append(
            "| {file} | {lanes} | {count} | {candidates} |".format(
                file=str(item.get("file", "")).replace("|", "\\|"),
                lanes=", ".join(item.get("lanes") or []),
                count=item.get("candidate_count", 0),
                candidates=candidates.replace("|", "\\|"),
            )
        )
    lines.append("")
    return "\n".join(lines)


def write_payload(payload: Dict[str, Any], *, out_json: Path, out_md: Path) -> None:
    out_json.parent.mkdir(parents=True, exist_ok=True)
    out_md.parent.mkdir(parents=True, exist_ok=True)
    out_json.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    out_md.write_text(render_markdown(payload), encoding="utf-8")


def parse_args(argv: Optional[Sequence[str]] = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Join deep_candidate.v1 records by cited file overlap."
    )
    parser.add_argument("--workspace", required=True, type=Path,
                        help="Audit workspace containing deep_candidates/.")
    parser.add_argument("--out-json", type=Path,
                        help="Output JSON path (default: <ws>/.audit_logs/cross_lane_correlations.json).")
    parser.add_argument("--out-md", type=Path,
                        help="Output Markdown path (default: <ws>/.audit_logs/cross_lane_correlations.md).")
    parser.add_argument("--print-json", action="store_true")
    return parser.parse_args(argv)


def main(argv: Optional[Sequence[str]] = None) -> int:
    args = parse_args(argv)
    ws = args.workspace.expanduser().resolve()
    if not ws.is_dir():
        print(f"[cross-lane-correlate] ERR workspace not found: {ws}", file=sys.stderr)
        return 2
    out_json = args.out_json or (ws / ".audit_logs" / "cross_lane_correlations.json")
    out_md = args.out_md or (ws / ".audit_logs" / "cross_lane_correlations.md")
    try:
        payload = build_payload(ws)
        write_payload(payload, out_json=out_json, out_md=out_md)
    except ValueError as exc:
        print(f"[cross-lane-correlate] ERR {exc}", file=sys.stderr)
        return 1
    if args.print_json:
        print(json.dumps(payload, indent=2, sort_keys=True))
    print(
        f"[cross-lane-correlate] OK correlations={payload['correlation_count']} "
        f"json={out_json} md={out_md}"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
