#!/usr/bin/env python3
"""
circom-detect.py - orchestrator for auditooor Circom detectors.

Runs every detector module under detectors/circom_wave1/ that exposes
`run_text(source, filepath)` against .circom files in a workspace and writes a
parseable log compatible with engage/workspace scan aggregation.
"""
from __future__ import annotations

import argparse
import importlib.util
import sys
import traceback
from pathlib import Path


REPO = Path(__file__).resolve().parent.parent
DETECTORS_DIR = REPO / "detectors" / "circom_wave1"
SKIP_PARTS = {
    ".git",
    "node_modules",
    "lib",
    "vendor",
    "test",
    "tests",
    "mocks",
    "build",
    "dist",
    "__pycache__",
}


def _load_detectors(only: str | None) -> list[tuple[str, object]]:
    detectors: list[tuple[str, object]] = []
    if not DETECTORS_DIR.exists():
        return detectors
    for path in sorted(DETECTORS_DIR.glob("*.py")):
        if path.name.startswith("_") or path.name.startswith("test_"):
            continue
        if only and path.stem != only:
            continue
        spec = importlib.util.spec_from_file_location(path.stem, path)
        if spec is None or spec.loader is None:
            continue
        module = importlib.util.module_from_spec(spec)
        try:
            spec.loader.exec_module(module)
        except Exception as exc:
            print(f"[warn] skipping detector {path.name}: {exc}", file=sys.stderr)
            continue
        if hasattr(module, "run_text"):
            detectors.append((path.stem, module))
    return detectors


def _discover(workspace: Path, single_file: Path | None) -> list[Path]:
    if single_file:
        return [single_file.resolve()]
    files: list[Path] = []
    for path in workspace.rglob("*.circom"):
        parts = set(path.resolve().parts)
        if parts & SKIP_PARTS:
            continue
        files.append(path.resolve())
    return sorted(set(files))


def _hit_line(path: Path, hit: dict) -> str:
    severity = str(hit.get("severity", "info")).upper()
    line = int(hit.get("line") or 0)
    col = int(hit.get("col") or 0)
    message = str(hit.get("message") or "")
    return f"  [{severity}] {path}:{line}:{col}  {message}\n"


def main() -> int:
    parser = argparse.ArgumentParser(description="Run Circom detectors.")
    parser.add_argument("workspace", type=Path, nargs="?", default=Path("."))
    parser.add_argument("--only", help="Run only this detector module stem.")
    parser.add_argument("--file", dest="single_file", type=Path)
    parser.add_argument("--log", type=Path, default=None)
    args = parser.parse_args()

    workspace = args.workspace.resolve()
    if not workspace.exists():
        print(f"[err] workspace not found: {workspace}", file=sys.stderr)
        return 2

    detectors = _load_detectors(args.only)
    if not detectors:
        print(f"[err] no Circom detectors under {DETECTORS_DIR}", file=sys.stderr)
        return 1

    files = _discover(workspace, args.single_file)
    if not files:
        print(f"[err] no .circom files found under {workspace}", file=sys.stderr)
        return 1

    log_path = args.log or (workspace / "audit" / "circom-detect.log")
    log_path.parent.mkdir(parents=True, exist_ok=True)

    hits_by_detector: dict[str, list[tuple[Path, dict]]] = {
        name: [] for name, _module in detectors
    }
    total = 0
    read_errors = 0
    detector_errors = 0

    for path in files:
        try:
            source = path.read_text(encoding="utf-8", errors="replace")
        except Exception as exc:
            read_errors += 1
            print(f"[warn] could not read {path}: {exc}", file=sys.stderr)
            continue
        for name, module in detectors:
            try:
                hits = module.run_text(source, str(path)) or []
            except Exception as exc:
                detector_errors += 1
                print(f"[warn] detector {name} crashed on {path}: {exc}", file=sys.stderr)
                traceback.print_exc(file=sys.stderr)
                continue
            for hit in hits:
                hits_by_detector[name].append((path, hit))
                total += 1

    with log_path.open("w", encoding="utf-8") as handle:
        handle.write("# circom-detect.log\n")
        handle.write(f"# workspace: {workspace}\n")
        handle.write(
            f"# files: {len(files)} read_errors: {read_errors} "
            f"detector_errors: {detector_errors} total_hits: {total}\n\n"
        )
        for name, _module in detectors:
            bucket = hits_by_detector[name]
            handle.write(f"=== {name}  ({len(bucket)} hits) ===\n")
            for path, hit in bucket:
                handle.write(_hit_line(path, hit))
                snippet = str(hit.get("snippet") or "")
                if snippet:
                    handle.write(f"      > {snippet}\n")
            handle.write("\n")

    print("=== per-detector hit counts ===")
    for name, _module in detectors:
        count = len(hits_by_detector[name])
        flag = "  NOISY" if count > 20 else ""
        print(f"  {count:4d}  {name}{flag}")
    print(f"\n[done] total hits: {total}   log: {log_path}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
