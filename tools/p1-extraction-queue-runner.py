#!/usr/bin/env python3
"""Run P1 fixture extraction queue rows with durable execution evidence.

The queue is produced by tools/p1-source-archive-map.py. This runner keeps the
execution step non-magical: it never shells out through a copied command string,
only accepts queue rows whose argv starts with the expected extractor, and
captures stdout/stderr for each attempted row.
"""
from __future__ import annotations

import argparse
import json
import subprocess
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Sequence


ROOT = Path(__file__).resolve().parents[1]
DEFAULT_QUEUE = ROOT / ".audit_logs" / "p1_fixture_extraction" / "extraction_queue.json"
DEFAULT_OUT = ROOT / ".audit_logs" / "p1_fixture_extraction" / "execution_manifest.json"
DEFAULT_OUT_MD = ROOT / ".audit_logs" / "p1_fixture_extraction" / "execution_report.md"
EXTRACTOR = "tools/p1-fixture-extractor.py"


def _load_queue(path: Path) -> list[dict[str, Any]]:
    data = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(data, list):
        raise ValueError("queue must be a JSON array")
    rows: list[dict[str, Any]] = []
    for idx, item in enumerate(data):
        if not isinstance(item, dict):
            raise ValueError(f"queue row {idx} is not an object")
        rows.append(item)
    return rows


def _safe_argv(item: dict[str, Any]) -> list[str]:
    raw = item.get("argv")
    if not isinstance(raw, list) or not all(isinstance(part, str) for part in raw):
        raise ValueError(f"queue row for {item.get('pattern', '<unknown>')} has invalid argv")
    if len(raw) < 2 or raw[0] != "python3" or raw[1] != EXTRACTOR:
        raise ValueError(f"queue row for {item.get('pattern', '<unknown>')} does not target {EXTRACTOR}")
    return [sys.executable, str(ROOT / EXTRACTOR), *raw[2:]]


def _append_unique(argv: list[str], flag: str, value: str | None = None) -> None:
    if flag in argv:
        return
    argv.append(flag)
    if value is not None:
        argv.append(value)


def _row_result_from_code(code: int) -> str:
    if code == 0:
        return "ok"
    if code == 2:
        return "cannot_run"
    return "failed"


def _write(path: Path, text: str) -> str:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text, encoding="utf-8")
    return str(path)


def run_queue(args: argparse.Namespace) -> dict[str, Any]:
    queue = _load_queue(args.queue)
    selected: list[dict[str, Any]] = []
    for item in queue:
        pattern = str(item.get("pattern", ""))
        if args.pattern and pattern != args.pattern:
            continue
        selected.append(item)
        if args.limit and len(selected) >= args.limit:
            break

    logs_dir = args.out.parent / "p1_extraction_logs"
    results: list[dict[str, Any]] = []
    for index, item in enumerate(selected, start=1):
        pattern = str(item.get("pattern", f"row-{index}"))
        result: dict[str, Any] = {
            "index": index,
            "pattern": pattern,
            "source": item.get("source", ""),
            "source_status": item.get("source_status", ""),
        }
        try:
            argv = _safe_argv(item)
        except ValueError as exc:
            result.update({"result": "invalid_queue_row", "error": str(exc)})
            results.append(result)
            if args.fail_fast:
                break
            continue

        if args.accept:
            _append_unique(argv, "--accept")
        if args.mock_dispatcher:
            _append_unique(argv, "--mock-dispatcher", str(args.mock_dispatcher))
        if args.runner:
            _append_unique(argv, "--runner", str(args.runner))
        if args.dsl_dir:
            _append_unique(argv, "--dsl-dir", str(args.dsl_dir))
        if args.fixture_dir:
            _append_unique(argv, "--fixture-dir", str(args.fixture_dir))
        if args.run_tests:
            _append_unique(argv, "--run-tests", str(args.run_tests))
        if args.skip_solc:
            _append_unique(argv, "--skip-solc")
        if args.no_minimax_review:
            _append_unique(argv, "--no-minimax-review")

        result["argv"] = argv
        if args.dry_run:
            result["result"] = "dry_run"
            results.append(result)
            continue

        proc = subprocess.run(
            argv,
            cwd=str(ROOT),
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            check=False,
        )
        safe_pattern = "".join(ch if ch.isalnum() or ch in "._-" else "_" for ch in pattern)
        stdout_path = logs_dir / f"{index:03d}_{safe_pattern}.stdout.txt"
        stderr_path = logs_dir / f"{index:03d}_{safe_pattern}.stderr.txt"
        result.update(
            {
                "exit_code": proc.returncode,
                "result": _row_result_from_code(proc.returncode),
                "stdout_path": _write(stdout_path, proc.stdout),
                "stderr_path": _write(stderr_path, proc.stderr),
            }
        )
        results.append(result)
        if args.fail_fast and proc.returncode != 0:
            break

    counts: dict[str, int] = {}
    for item in results:
        key = str(item.get("result", "unknown"))
        counts[key] = counts.get(key, 0) + 1
    return {
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "queue": str(args.queue),
        "selected_count": len(selected),
        "result_counts": counts,
        "dry_run": bool(args.dry_run),
        "accept": bool(args.accept),
        "results": results,
    }


def render_markdown(manifest: dict[str, Any]) -> str:
    lines = [
        "# P1 Extraction Execution Report",
        "",
        f"- Queue: `{manifest['queue']}`",
        f"- Selected rows: `{manifest['selected_count']}`",
        f"- Dry run: `{manifest['dry_run']}`",
        f"- Accept mode: `{manifest['accept']}`",
        "",
        "## Result Counts",
        "",
    ]
    counts = manifest.get("result_counts", {})
    if counts:
        for key in sorted(counts):
            lines.append(f"- `{key}`: `{counts[key]}`")
    else:
        lines.append("- No rows selected.")
    lines.extend([
        "",
        "## Rows",
        "",
        "| # | Pattern | Source | Result | Evidence |",
        "|---|---|---|---|---|",
    ])
    for row in manifest.get("results", []):
        evidence_parts: list[str] = []
        if row.get("stdout_path"):
            evidence_parts.append(f"stdout: `{row['stdout_path']}`")
        if row.get("stderr_path"):
            evidence_parts.append(f"stderr: `{row['stderr_path']}`")
        if row.get("error"):
            evidence_parts.append(f"error: `{row['error']}`")
        if not evidence_parts and row.get("argv"):
            evidence_parts.append("dry-run argv recorded")
        lines.append(
            f"| `{row.get('index', '')}` | `{row.get('pattern', '')}` | "
            f"`{row.get('source', '')}` | `{row.get('result', '')}` | "
            f"{'; '.join(evidence_parts)} |"
        )
    lines.extend([
        "",
        "## Guardrails",
        "",
        "- `ok` means the extractor row completed; review stdout and fixture diff before merge.",
        "- `ACCEPT=1` should be used only after reviewing a prior non-accept manifest or on a tightly scoped row.",
        "- Fixture promotion still requires vulnerable hits >= 1, clean hits == 0, and normal Codex review.",
    ])
    return "\n".join(lines) + "\n"


def parse_args(argv: Sequence[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--queue", type=Path, default=DEFAULT_QUEUE)
    parser.add_argument("--out", type=Path, default=DEFAULT_OUT)
    parser.add_argument("--out-md", type=Path, default=DEFAULT_OUT_MD)
    parser.add_argument("--pattern", help="Run only one pattern from the queue")
    parser.add_argument("--limit", type=int, default=0, help="Maximum queue rows to run. 0 means all selected rows.")
    parser.add_argument("--dry-run", action="store_true", help="Write manifest without invoking extractor rows")
    parser.add_argument("--accept", action="store_true", help="Pass --accept through to p1-fixture-extractor.py")
    parser.add_argument("--fail-fast", action="store_true")
    parser.add_argument("--mock-dispatcher", type=Path, help="Test-only dispatcher passed through to extractor")
    parser.add_argument("--runner", type=Path, help="Detector runner override passed through to extractor")
    parser.add_argument("--dsl-dir", type=Path)
    parser.add_argument("--fixture-dir", type=Path)
    parser.add_argument("--run-tests", type=Path)
    parser.add_argument("--skip-solc", action="store_true")
    parser.add_argument("--no-minimax-review", action="store_true")
    parser.add_argument("--print-json", action="store_true")
    return parser.parse_args(argv)


def main(argv: Sequence[str] | None = None) -> int:
    args = parse_args(argv)
    manifest = run_queue(args)
    args.out.parent.mkdir(parents=True, exist_ok=True)
    args.out.write_text(json.dumps(manifest, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    if args.out_md:
        args.out_md.parent.mkdir(parents=True, exist_ok=True)
        args.out_md.write_text(render_markdown(manifest), encoding="utf-8")
    if args.print_json:
        print(json.dumps(manifest, indent=2, sort_keys=True))
    return 0 if not any(row.get("result") in {"failed", "invalid_queue_row"} for row in manifest["results"]) else 1


if __name__ == "__main__":
    raise SystemExit(main())
