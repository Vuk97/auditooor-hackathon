#!/usr/bin/env python3
"""Materialize scanner-autonomy semantic repair fixtures into canonical smoke rows."""
from __future__ import annotations

import argparse
import json
import os
import re
import shutil
import subprocess
import sys
from pathlib import Path
from typing import Any


SCHEMA = "auditooor.scanner_autonomy_canonical_fixture_materialization.v1"


def _read_json(path: Path) -> dict[str, Any]:
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return {}
    return payload if isinstance(payload, dict) else {}


def _write_json(path: Path, payload: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def _write_text(path: Path, text: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text, encoding="utf-8")


def _slug(pattern: str) -> str:
    return re.sub(r"[^A-Za-z0-9]+", "_", pattern).strip("_").lower()


def _hits(output: str) -> int | None:
    match = re.search(r"total hits:\s*(\d+)", output, re.I)
    return int(match.group(1)) if match else None


def _runner_python(preferred: str | None) -> str:
    if preferred and Path(preferred).is_file():
        return preferred
    homebrew = Path("/opt/homebrew/bin/python3.13")
    if homebrew.is_file():
        return str(homebrew)
    return sys.executable


def _run_smoke(workspace: Path, runner_python: str, fixture: Path, pattern: str) -> dict[str, Any]:
    env = os.environ.copy()
    env["AUDITOOOR_FIXTURE_SMOKE_MODE"] = "1"
    env.setdefault("AUDITOOOR_SLITHER_NOCACHE", "1")
    argv = [
        runner_python,
        str(workspace / "detectors" / "run_custom.py"),
        str(fixture),
        pattern,
        "--tier=ALL",
    ]
    proc = subprocess.run(
        argv,
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        check=False,
        env=env,
    )
    return {
        "argv": argv,
        "command": "AUDITOOOR_FIXTURE_SMOKE_MODE=1 AUDITOOOR_SLITHER_NOCACHE=1 " + " ".join(argv),
        "env_overrides": {
            "AUDITOOOR_FIXTURE_SMOKE_MODE": "1",
            "AUDITOOOR_SLITHER_NOCACHE": env.get("AUDITOOOR_SLITHER_NOCACHE", "1"),
        },
        "returncode": proc.returncode,
        "stdout": proc.stdout,
        "total_hits": _hits(proc.stdout),
    }


def _safe_copy(src: Path, dst: Path, *, overwrite: bool) -> tuple[bool, str]:
    if not src.is_file():
        return False, "synthetic_fixture_missing"
    if dst.exists() and not overwrite:
        if dst.read_text(encoding="utf-8") == src.read_text(encoding="utf-8"):
            return True, "already_materialized"
        return False, "canonical_fixture_exists_with_different_content"
    dst.parent.mkdir(parents=True, exist_ok=True)
    shutil.copyfile(src, dst)
    return True, "materialized"


def _iter_manifests(manifest_dir: Path) -> list[Path]:
    return sorted(path for path in manifest_dir.glob("ssi-fix-*.json") if path.is_file())


def materialize(workspace: Path, *, limit: int | None, overwrite: bool, runner_python: str) -> dict[str, Any]:
    manifest_dir = workspace / ".auditooor" / "scanner_autonomy_semantic_repair_manifests"
    out_dir = workspace / ".auditooor" / "scanner_autonomy_canonical_fixture_materialization"
    rows: list[dict[str, Any]] = []
    selected = _iter_manifests(manifest_dir)
    if limit is not None:
        selected = selected[:limit]

    for manifest_path in selected:
        manifest = _read_json(manifest_path)
        source_id = str(manifest.get("source_id") or manifest_path.stem)
        pattern = str(manifest.get("pattern") or "")
        row: dict[str, Any] = {
            "source_id": source_id,
            "pattern": pattern,
            "input_manifest": str(manifest_path),
            "promotion_allowed": False,
            "submission_posture": "NOT_SUBMIT_READY",
            "coverage_claim": "detector_fixture_smoke_only",
        }
        if not manifest.get("materialization_ready"):
            row.update({"status": "blocked_manifest_not_materialization_ready", "blockers": ["manifest_not_materialization_ready"]})
            rows.append(row)
            continue
        if not pattern:
            row.update({"status": "blocked_missing_pattern", "blockers": ["missing_pattern"]})
            rows.append(row)
            continue

        vuln_src = Path(str(manifest.get("synthetic_vulnerable_fixture") or ""))
        clean_src = Path(str(manifest.get("synthetic_clean_fixture") or ""))
        vuln_dst = Path(str(manifest.get("canonical_vulnerable_fixture") or ""))
        clean_dst = Path(str(manifest.get("canonical_clean_fixture") or ""))
        row.update({
            "synthetic_vulnerable_fixture": str(vuln_src),
            "synthetic_clean_fixture": str(clean_src),
            "canonical_vulnerable_fixture": str(vuln_dst),
            "canonical_clean_fixture": str(clean_dst),
        })
        if not str(vuln_dst).startswith(str(workspace / "detectors" / "test_fixtures")):
            row.update({"status": "blocked_unsafe_canonical_path", "blockers": ["canonical_path_outside_detectors_test_fixtures"]})
            rows.append(row)
            continue

        ok_v, status_v = _safe_copy(vuln_src, vuln_dst, overwrite=overwrite)
        ok_c, status_c = _safe_copy(clean_src, clean_dst, overwrite=overwrite)
        row["materialization"] = {"vulnerable": status_v, "clean": status_c}
        if not ok_v or not ok_c:
            row.update({"status": "blocked_materialization_failed", "blockers": [status_v, status_c]})
            rows.append(row)
            continue

        vuln_smoke = _run_smoke(workspace, runner_python, vuln_dst, pattern)
        clean_smoke = _run_smoke(workspace, runner_python, clean_dst, pattern)
        vuln_hits = vuln_smoke.get("total_hits")
        clean_hits = clean_smoke.get("total_hits")
        passed = (
            vuln_smoke.get("returncode") == 0
            and clean_smoke.get("returncode") == 0
            and isinstance(vuln_hits, int)
            and isinstance(clean_hits, int)
            and vuln_hits >= 1
            and clean_hits == 0
        )
        slug = _slug(pattern)
        smoke_record = {
            "schema": "auditooor.canonical_detector_fixture_smoke.v1",
            "source_id": source_id,
            "pattern": pattern,
            "status": "passed_vulnerable_clean_smoke" if passed else "failed_vulnerable_clean_smoke",
            "positive_fixture_path": str(vuln_dst),
            "clean_fixture_path": str(clean_dst),
            "positive_hits": vuln_hits,
            "clean_hits": clean_hits,
            "vulnerable_smoke": vuln_smoke,
            "clean_smoke": clean_smoke,
            "coverage_claim": "detector_fixture_smoke_only",
            "promotion_allowed": False,
            "submission_posture": "NOT_SUBMIT_READY",
        }
        smoke_path = out_dir / f"{slug}_smoke.json"
        fixture_manifest_path = workspace / "detectors" / "test_fixtures" / f"{slug}_semantic_manifest.json"
        _write_json(smoke_path, smoke_record)
        _write_json(
            fixture_manifest_path,
            {
                "schema": "auditooor.semantic_fixture_materialization.v1",
                "fixture_id": source_id,
                "detector_slug": slug,
                "pattern": pattern,
                "materialization_status": "canonical_semantic_fixture_smoke_passed" if passed else "canonical_semantic_fixture_smoke_failed",
                "positive_fixture_path": str(vuln_dst),
                "clean_fixture_path": str(clean_dst),
                "smoke_record_path": str(smoke_path),
                "coverage_claim": "detector_fixture_smoke_only",
                "promotion_allowed": False,
                "submission_posture": "NOT_SUBMIT_READY",
                "source_semantic_repair_manifest": str(manifest_path),
                "terminal_fixture_evidence": passed,
            },
        )
        row.update({
            "status": "canonical_smoke_passed" if passed else "canonical_smoke_failed",
            "positive_hits": vuln_hits,
            "clean_hits": clean_hits,
            "smoke_record_path": str(smoke_path),
            "fixture_manifest_path": str(fixture_manifest_path),
            "blockers": [] if passed else ["canonical_vulnerable_clean_smoke_failed"],
        })
        rows.append(row)

    status_counts: dict[str, int] = {}
    for row in rows:
        status = str(row.get("status") or "unknown")
        status_counts[status] = status_counts.get(status, 0) + 1
    payload = {
        "schema": SCHEMA,
        "workspace": str(workspace),
        "input_manifest_dir": str(manifest_dir),
        "selected_count": len(selected),
        "rows": rows,
        "status_counts": status_counts,
        "canonical_smoke_passed_count": status_counts.get("canonical_smoke_passed", 0),
        "canonical_smoke_failed_count": status_counts.get("canonical_smoke_failed", 0),
        "blocked_count": sum(count for status, count in status_counts.items() if status.startswith("blocked")),
        "coverage_claim": "detector_fixture_smoke_only",
        "promotion_allowed": False,
        "submission_posture": "NOT_SUBMIT_READY",
    }
    _write_json(workspace / ".auditooor" / "scanner_autonomy_canonical_fixture_materialization.json", payload)
    lines = [
        "# Scanner Autonomy Canonical Fixture Materialization",
        "",
        f"- selected manifests: {payload['selected_count']}",
        f"- canonical smoke passed: {payload['canonical_smoke_passed_count']}",
        f"- canonical smoke failed: {payload['canonical_smoke_failed_count']}",
        f"- blocked: {payload['blocked_count']}",
        "- boundary: detector fixture smoke only; no finding proof or submission-readiness claim",
        "",
        "## Rows",
    ]
    for row in rows:
        lines.append(f"- {row.get('source_id')}: {row.get('status')} ({row.get('pattern')})")
    _write_text(workspace / ".auditooor" / "scanner_autonomy_canonical_fixture_materialization.md", "\n".join(lines) + "\n")
    return payload


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--workspace", default=".", help="Auditooor workspace")
    parser.add_argument("--manifest-dir", default="", help="Reserved for compatibility; defaults to workspace manifest dir")
    parser.add_argument("--limit", type=int, default=None, help="Limit number of manifests")
    parser.add_argument("--overwrite", action="store_true", help="Overwrite existing canonical fixture files")
    parser.add_argument("--runner-python", default="", help="Python interpreter for detectors/run_custom.py")
    parser.add_argument("--print-json", action="store_true", help="Print JSON summary")
    args = parser.parse_args()
    workspace = Path(args.workspace).resolve()
    runner_python = _runner_python(args.runner_python or None)
    payload = materialize(workspace, limit=args.limit, overwrite=args.overwrite, runner_python=runner_python)
    if args.print_json:
        print(json.dumps(payload, indent=2, sort_keys=True))
    return 0 if payload["canonical_smoke_passed_count"] or not payload["selected_count"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
