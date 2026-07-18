#!/usr/bin/env python3
"""inventory-smoke-test.py — auto-tier every wave detector against its fixtures.

For each wave detector .py on disk:
  1. Locate ARGUMENT (kebab-case slither name) and detector_id (snake)
  2. Skip if YAML has `status: documentation_only`
  3. Locate vulnerable + clean fixtures (try multiple conventions)
  4. Skip if either fixture is missing
  5. Run `python3 detectors/run_custom.py --tier=ALL <fixture> <ARGUMENT>` for each
  6. Record clean_hits / vuln_hits
  7. Classify status:
       smoke_pass     → clean=0, vuln>=1
       false_positive → clean>0
       silent         → clean=0, vuln=0
       skipped_docs   → YAML status: documentation_only
       skipped_no_fix → no fixture pair on disk
       parse_error    → run_custom didn't emit [done] line
       duplicate      → multiple .py files share the same ARGUMENT (dedupe to first)

Output:
  inventory_smoke_summary.json     — full per-detector result
  inventory_smoke_passing.txt      — list of ARGUMENTs that passed
  inventory_smoke_promote_queue.json — bulk-promote payload for _tier_registry.yaml

Usage:
  python3 tools/inventory-smoke-test.py \\
    --output-dir /private/tmp/auditooor-inventory \\
    [--limit N] [--workers 4] [--include-graveyard] [--detector ARG]

Doesn't mutate _tier_registry.yaml. Bulk promotion is a separate step
(`tools/inventory-bulk-promote.py`, written next, reads the promote_queue.json).
"""
from __future__ import annotations

import argparse
import concurrent.futures as futures
import datetime
import json
import os
import re
import shutil
import subprocess
import sys
import time
from pathlib import Path

REPO = Path(__file__).resolve().parents[1]
DETECTORS_DIR = REPO / "detectors"
RUN_CUSTOM = DETECTORS_DIR / "run_custom.py"
DSL_DIR = REPO / "reference" / "patterns.dsl"
_SLITHER_PYTHON_CACHE: tuple[tuple[str, ...], str] | None = None
FIXTURE_PATHS = [
    # Convention A — snake_case at detectors/test_fixtures/
    lambda arg, snake: REPO / "detectors" / "test_fixtures" / f"{snake}_vulnerable.sol",
    lambda arg, snake: REPO / "detectors" / "test_fixtures" / f"{snake}_clean.sol",
    # Convention B — kebab-case at patterns/fixtures/ with _vuln/_clean
    lambda arg, snake: REPO / "patterns" / "fixtures" / f"{arg}_vuln.sol",
    lambda arg, snake: REPO / "patterns" / "fixtures" / f"{arg}_clean.sol",
    # Convention C — kebab-case at patterns/fixtures/ with _vulnerable/_clean
    lambda arg, snake: REPO / "patterns" / "fixtures" / f"{arg}_vulnerable.sol",
]

_DONE_HITS_RE = re.compile(r"\[done\]\s+total hits:\s+(\d+)")
_ARGUMENT_RE = re.compile(r'^\s*ARGUMENT\s*=\s*[\'"]([\w\-]+)[\'"]', re.MULTILINE)


def _python_candidates() -> list[str]:
    candidates: list[str] = []
    for env_name in ("AUDITOOOR_PYTHON_SLITHER", "SLITHER_PYTHON"):
        env_python = os.environ.get(env_name)
        if env_python:
            candidates.append(env_python)
    candidates.append(sys.executable)
    for name in ("python3", "python3.14", "python3.13", "python3.12", "python3.11", "python"):
        found = shutil.which(name)
        if found:
            candidates.append(found)

    deduped: list[str] = []
    seen: set[str] = set()
    for candidate in candidates:
        if candidate and candidate not in seen:
            seen.add(candidate)
            deduped.append(candidate)
    return deduped


def _portable_runner_python() -> str:
    fallback = ""
    for candidate in _python_candidates():
        name = Path(candidate).name.strip()
        if name.startswith("python3"):
            return "python3"
        if not fallback and name == "python":
            fallback = "python"
    return fallback or "python3"


def _python_imports_module(python_bin: str, module: str) -> bool:
    try:
        proc = subprocess.run(
            [
                python_bin,
                "-c",
                "import importlib.util, sys; "
                f"sys.exit(0 if importlib.util.find_spec({module!r}) else 1)",
            ],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            text=True,
            check=False,
            timeout=5,
        )
    except (OSError, subprocess.TimeoutExpired):
        return False
    return proc.returncode == 0


def _slither_python() -> str:
    global _SLITHER_PYTHON_CACHE
    candidates = tuple(_python_candidates())
    if _SLITHER_PYTHON_CACHE and _SLITHER_PYTHON_CACHE[0] == candidates:
        return _SLITHER_PYTHON_CACHE[1]

    for python_bin in candidates:
        if (
            _python_imports_module(python_bin, "slither")
            and _python_imports_module(python_bin, "slither.detectors.abstract_detector")
        ):
            _SLITHER_PYTHON_CACHE = (candidates, python_bin)
            return python_bin

    _SLITHER_PYTHON_CACHE = (candidates, "")
    return ""


def _fixture_command(
    arg: str,
    fixture: Path,
    *,
    include_graveyard: bool = False,
    runner_python: str | None = None,
) -> str:
    fixture_rel = fixture.relative_to(REPO) if fixture.is_relative_to(REPO) else fixture
    parts = [
        "AUDITOOOR_FIXTURE_SMOKE_MODE=1",
        "AUDITOOOR_SLITHER_NOCACHE=1",
        runner_python or _portable_runner_python(),
        str(RUN_CUSTOM.relative_to(REPO)),
    ]
    if include_graveyard:
        parts.append("--include-graveyard")
    parts.extend(["--tier=ALL", str(fixture_rel), arg])
    return " ".join(parts)


def _smoke_metadata(py_path: Path, arg: str, vuln: Path, clean: Path) -> dict[str, str]:
    include_graveyard = "wave_graveyard" in py_path.parts
    runner_python = _portable_runner_python()
    return {
        "runner_python": runner_python,
        "positive_command": _fixture_command(
            arg,
            vuln,
            include_graveyard=include_graveyard,
            runner_python=runner_python,
        ),
        "clean_command": _fixture_command(
            arg,
            clean,
            include_graveyard=include_graveyard,
            runner_python=runner_python,
        ),
    }


def discover_detectors(include_graveyard: bool = False) -> list[Path]:
    """Find every wave detector .py on disk."""
    paths: list[Path] = []
    for wave_dir in DETECTORS_DIR.glob("wave*"):
        if not wave_dir.is_dir():
            continue
        if "graveyard" in wave_dir.name and not include_graveyard:
            continue
        for py in wave_dir.glob("*.py"):
            if py.name.startswith("_") or py.name == "__init__.py":
                continue
            paths.append(py)
    if include_graveyard:
        for py in DETECTORS_DIR.glob("wave_graveyard/wave*/*.py"):
            if py.name.startswith("_") or py.name == "__init__.py":
                continue
            paths.append(py)
    # Also detectors/wave1/, detectors/wave_overnight/ etc.
    return sorted(paths)


def extract_argument(py_path: Path) -> str | None:
    """Read ARGUMENT = "..." from a .py file."""
    try:
        text = py_path.read_text(encoding="utf-8", errors="replace")
    except Exception:
        return None
    m = _ARGUMENT_RE.search(text)
    return m.group(1) if m else None


def resolve_selected_detector_paths(
    paths: list[Path],
    selector: str,
    extract_argument_fn=None,
) -> list[Path]:
    """Resolve exactly one detector path by exact ARGUMENT."""
    extract_fn = extract_argument_fn or extract_argument
    matches: list[Path] = []
    for path in paths:
        if extract_fn(path) == selector:
            matches.append(path)
    if not matches:
        raise ValueError(f"unknown detector: {selector}")
    if len(matches) > 1:
        rels = ", ".join(str(p.relative_to(REPO)) for p in matches)
        raise ValueError(f"duplicate detector argument {selector}: {rels}")
    return matches


def resolve_selected_detector_path(paths: list[Path], selector: str) -> list[Path]:
    """Resolve exactly one detector by repo-relative or absolute .py path."""
    selected = Path(selector)
    if not selected.is_absolute():
        selected = REPO / selected
    selected = selected.resolve()
    by_resolved = {path.resolve(): path for path in paths}
    match = by_resolved.get(selected)
    if not match:
        raise ValueError(f"unknown detector path: {selector}")
    return [match]


def yaml_status(arg: str) -> str | None:
    """Return 'documentation_only' / 'live' / None (no YAML)."""
    yaml_path = DSL_DIR / f"{arg}.yaml"
    if not yaml_path.exists():
        return None
    try:
        text = yaml_path.read_text(encoding="utf-8", errors="replace")
    except Exception:
        return None
    if re.search(r"^\s*status\s*:\s*documentation[_-]?only\b", text, re.MULTILINE | re.IGNORECASE):
        return "documentation_only"
    return "live"


def _read_json(path: Path) -> dict | None:
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return None
    return payload if isinstance(payload, dict) else None


def _resolve_fixture_pointer(raw: str, metadata_path: Path, repo: Path = REPO) -> Path | None:
    path = Path(raw)
    candidates = [path] if path.is_absolute() else [repo / path, metadata_path.parent / path]
    for candidate in candidates:
        if candidate.exists():
            return candidate
    return None


def _metadata_binds_detector(payload: dict, arg: str, repo: Path = REPO) -> bool:
    snake = arg.replace("-", "_")
    pattern = payload.get("pattern")
    detector_slug = payload.get("detector_slug")
    detector_path = payload.get("detector_path")
    bindings: list[bool] = []
    if isinstance(pattern, str) and pattern.strip():
        bindings.append(pattern.strip() == arg)
    if isinstance(detector_slug, str) and detector_slug.strip():
        bindings.append(detector_slug.strip() == snake)
    if isinstance(detector_path, str) and detector_path.strip():
        expected = f"{snake}.py"
        candidate = Path(detector_path.strip())
        if not candidate.is_absolute():
            candidate = repo / candidate
        bindings.append(candidate.name == expected)
    return bool(bindings) and all(bindings)


def _metadata_fixture_pair(arg: str, repo: Path = REPO) -> tuple[Path | None, Path | None]:
    snake = arg.replace("-", "_")
    fixture_dirs = [
        repo / "detectors" / "fixtures" / snake,
        repo / "detectors" / "fixtures" / arg,
    ]
    positive_keys = (
        "positive_fixture",
        "positive_fixture_path",
        "vulnerable_fixture",
        "vulnerable_fixture_path",
    )
    clean_keys = (
        "clean_fixture",
        "clean_fixture_path",
        "negative_fixture",
        "negative_fixture_path",
    )
    for fixture_dir in fixture_dirs:
        for metadata_name in ("smoke.json", "manifest.json"):
            metadata_path = fixture_dir / metadata_name
            payload = _read_json(metadata_path)
            if not payload:
                continue
            if not _metadata_binds_detector(payload, arg, repo):
                continue
            positive: Path | None = None
            clean: Path | None = None
            for key in positive_keys:
                value = payload.get(key)
                if isinstance(value, str) and value.strip():
                    positive = _resolve_fixture_pointer(value.strip(), metadata_path, repo)
                    if positive:
                        break
            for key in clean_keys:
                value = payload.get(key)
                if isinstance(value, str) and value.strip():
                    clean = _resolve_fixture_pointer(value.strip(), metadata_path, repo)
                    if clean:
                        break
            fixtures = payload.get("fixtures")
            if isinstance(fixtures, dict):
                if not positive:
                    for key in ("positive", "vulnerable"):
                        value = fixtures.get(key)
                        if isinstance(value, str) and value.strip():
                            positive = _resolve_fixture_pointer(value.strip(), metadata_path, repo)
                            if positive:
                                break
                if not clean:
                    for key in ("clean", "negative"):
                        value = fixtures.get(key)
                        if isinstance(value, str) and value.strip():
                            clean = _resolve_fixture_pointer(value.strip(), metadata_path, repo)
                            if clean:
                                break
            if positive or clean:
                return positive, clean
    return None, None


def find_fixtures(arg: str) -> tuple[Path | None, Path | None]:
    """Return (vulnerable_path, clean_path), each path or None."""
    snake = arg.replace("-", "_")
    candidates_v: list[Path] = []
    candidates_c: list[Path] = []
    metadata_v, metadata_c = _metadata_fixture_pair(arg)
    if metadata_v:
        candidates_v.append(metadata_v)
    if metadata_c:
        candidates_c.append(metadata_c)
    # Convention A
    candidates_v.append(REPO / "detectors" / "test_fixtures" / f"{snake}_vulnerable.sol")
    candidates_c.append(REPO / "detectors" / "test_fixtures" / f"{snake}_clean.sol")
    # Convention A2 — canonical per-detector fixture directories.
    fixture_dir = REPO / "detectors" / "fixtures" / snake
    candidates_v.extend(
        [
            fixture_dir / "positive.sol",
            fixture_dir / "vulnerable.sol",
            fixture_dir / f"{snake}_vulnerable.sol",
        ]
    )
    candidates_c.extend(
        [
            fixture_dir / "clean.sol",
            fixture_dir / "negative.sol",
            fixture_dir / f"{snake}_clean.sol",
        ]
    )
    # Convention B (vuln)
    candidates_v.append(REPO / "patterns" / "fixtures" / f"{arg}_vuln.sol")
    candidates_c.append(REPO / "patterns" / "fixtures" / f"{arg}_clean.sol")
    # Convention C (vulnerable)
    candidates_v.append(REPO / "patterns" / "fixtures" / f"{arg}_vulnerable.sol")
    # Convention D — broken-wave local fixtures kept under detectors/wave14_broken/
    candidates_v.append(REPO / "detectors" / "wave14_broken" / f"{snake}_vulnerable.sol")
    candidates_c.append(REPO / "detectors" / "wave14_broken" / f"{snake}_clean.sol")
    vuln = next((p for p in candidates_v if p.exists()), None)
    clean = next((p for p in candidates_c if p.exists()), None)
    return vuln, clean


def run_smoke(
    arg: str,
    fixture: Path,
    timeout_sec: int = 90,
    *,
    include_graveyard: bool = False,
) -> tuple[int, str]:
    """Run run_custom.py against one fixture+arg. Return (hits, last_3_lines_of_output).
    hits = -1 means parse error / timeout / process failure.
    """
    python_bin = _slither_python()
    if not python_bin:
        return (
            -1,
            "MISSING_SLITHER_ANALYZER: set AUDITOOOR_PYTHON_SLITHER or install slither-analyzer",
        )
    cmd = [python_bin, str(RUN_CUSTOM)]
    if include_graveyard:
        cmd.append("--include-graveyard")
    cmd.extend(["--tier=ALL", str(fixture), arg])
    # Fixture-smoke mode: bypass the path-based vendored/test filter so
    # contracts living under patterns/fixtures/ are not auto-skipped (the
    # filter substring "/fixtures/" otherwise hides every smoke target).
    smoke_env = os.environ.copy()
    smoke_env["AUDITOOOR_FIXTURE_SMOKE_MODE"] = "1"
    try:
        proc = subprocess.run(
            cmd, capture_output=True, text=True, timeout=timeout_sec, cwd=REPO,
            env=smoke_env,
        )
    except subprocess.TimeoutExpired:
        return (-1, "TIMEOUT")
    out = (proc.stdout or "") + "\n" + (proc.stderr or "")
    m = _DONE_HITS_RE.search(out)
    if m is None:
        # Either docs-only (returned without firing) or process fail.
        tail = "\n".join(out.splitlines()[-3:])[:300]
        return (-1, f"NO_DONE_LINE: {tail}")
    return (int(m.group(1)), "")


def smoke_one(py_path: Path) -> dict:
    """Process one detector .py. Returns a result dict."""
    result = {
        "py_path": str(py_path.relative_to(REPO)),
        "wave": py_path.parent.name,
        "argument": None,
        "yaml_status": None,
        "vuln_fixture": None,
        "clean_fixture": None,
        "vuln_hits": None,
        "clean_hits": None,
        "status": "?",
        "notes": "",
        "smoke_metadata": None,
    }
    arg = extract_argument(py_path)
    if not arg:
        result["status"] = "skipped_no_argument"
        return result
    result["argument"] = arg
    yaml_st = yaml_status(arg)
    result["yaml_status"] = yaml_st
    if yaml_st == "documentation_only":
        result["status"] = "skipped_docs"
        return result
    vuln, clean = find_fixtures(arg)
    if not (vuln and clean):
        result["vuln_fixture"] = str(vuln.relative_to(REPO)) if vuln else None
        result["clean_fixture"] = str(clean.relative_to(REPO)) if clean else None
        result["status"] = "skipped_no_fix"
        return result
    result["vuln_fixture"] = str(vuln.relative_to(REPO))
    result["clean_fixture"] = str(clean.relative_to(REPO))
    result["smoke_metadata"] = _smoke_metadata(py_path, arg, vuln, clean)
    include_graveyard = "wave_graveyard" in py_path.parts
    vh, vnote = run_smoke(arg, vuln, include_graveyard=include_graveyard)
    ch, cnote = run_smoke(arg, clean, include_graveyard=include_graveyard)
    result["vuln_hits"] = vh
    result["clean_hits"] = ch
    if vh < 0 or ch < 0:
        result["status"] = "parse_error"
        result["notes"] = f"vuln_note={vnote}; clean_note={cnote}"
    elif ch == 0 and vh >= 1:
        result["status"] = "smoke_pass"
    elif ch > 0:
        result["status"] = "false_positive"
    else:
        result["status"] = "silent"
    return result


def parse_args(argv=None):
    ap = argparse.ArgumentParser()
    ap.add_argument("--output-dir", required=True)
    ap.add_argument("--limit", type=int, default=0, help="Process at most N detectors (0 = all).")
    ap.add_argument("--workers", type=int, default=4, help="Parallel workers (default 4).")
    ap.add_argument("--include-graveyard", action="store_true")
    ap.add_argument("--detector", default=None, help="Run only this exact detector ARGUMENT.")
    ap.add_argument("--detector-path", default=None, help="Run only this detector .py path.")
    args = ap.parse_args(argv)
    if args.detector and args.limit:
        ap.error("--detector cannot be combined with --limit")
    if args.detector_path and args.limit:
        ap.error("--detector-path cannot be combined with --limit")
    if args.detector and args.detector_path:
        ap.error("--detector and --detector-path are mutually exclusive")
    return args


def main(argv=None) -> int:
    args = parse_args(argv)

    out_dir = Path(args.output_dir)
    out_dir.mkdir(parents=True, exist_ok=True)

    if os.environ.get("AUDITOOOR_FIXTURE_SMOKE_MODE") != "1":
        print(
            "[warn] AUDITOOOR_FIXTURE_SMOKE_MODE not set in parent env. "
            "run_smoke() will inject it per subprocess, but it is best to export it "
            "in the shell (foot-gun #20). Use: AUDITOOOR_FIXTURE_SMOKE_MODE=1 python3 ... "
            "or: make inventory-smoke",
            file=sys.stderr,
        )

        paths = discover_detectors(include_graveyard=args.include_graveyard)
    else:
        paths = discover_detectors(include_graveyard=args.include_graveyard)

    if args.detector_path:
        try:
            paths = resolve_selected_detector_path(paths, args.detector_path)
        except ValueError as e:
            print(f"[fatal] {e}", file=sys.stderr)
            return 2
        print(
            f"[select] detector_path={paths[0].relative_to(REPO)}",
            flush=True,
        )
    elif args.detector:
        try:
            paths = resolve_selected_detector_paths(paths, args.detector)
        except ValueError as e:
            print(f"[fatal] {e}", file=sys.stderr)
            return 2
        print(
            f"[select] detector={args.detector} path={paths[0].relative_to(REPO)}",
            flush=True,
        )
    if args.limit:
        paths = paths[: args.limit]
    print(f"[inventory] discovered {len(paths)} detector .py files; running with {args.workers} workers...", flush=True)

    seen_args: dict[str, dict] = {}
    duplicates: list[dict] = []
    started = time.time()
    completed = 0

    def _on_result(r: dict):
        nonlocal completed
        completed += 1
        arg = r.get("argument")
        if arg and arg in seen_args:
            duplicates.append({
                "argument": arg,
                "first_path": seen_args[arg]["py_path"],
                "duplicate_path": r["py_path"],
            })
            r["status"] = "duplicate"
        elif arg:
            seen_args[arg] = r
        if completed % 50 == 0 or completed == len(paths):
            elapsed = time.time() - started
            rate = completed / elapsed if elapsed else 0
            eta = (len(paths) - completed) / rate if rate else 0
            print(f"  [{completed:5d}/{len(paths)}] {rate:.1f}/s  ETA {eta/60:.0f}m", flush=True)

    results: list[dict] = []
    if args.workers <= 1:
        for p in paths:
            r = smoke_one(p)
            _on_result(r)
            results.append(r)
    else:
        with futures.ThreadPoolExecutor(max_workers=args.workers) as ex:
            futs = {ex.submit(smoke_one, p): p for p in paths}
            for fut in futures.as_completed(futs):
                try:
                    r = fut.result()
                except Exception as e:
                    r = {"py_path": str(futs[fut].relative_to(REPO)), "status": "exception",
                         "notes": str(e), "argument": None}
                _on_result(r)
                results.append(r)

    by_status: dict[str, int] = {}
    for r in results:
        s = r.get("status", "?")
        by_status[s] = by_status.get(s, 0) + 1

    summary = {
        "schema": "auditooor.inventory_smoke.v1",
        "ran_at": datetime.datetime.now(datetime.timezone.utc).isoformat(),
        "total_detectors_scanned": len(results),
        "by_status": by_status,
        "duplicate_count": len(duplicates),
        "duplicates": duplicates,
        "results": results,
    }
    (out_dir / "inventory_smoke_summary.json").write_text(json.dumps(summary, indent=2))

    passing = [r for r in results if r["status"] == "smoke_pass"]
    (out_dir / "inventory_smoke_passing.txt").write_text(
        "\n".join(sorted(r["argument"] for r in passing if r["argument"])) + "\n"
    )
    promote_queue = [
        {
            "argument": r["argument"],
            "py_path": r["py_path"],
            "wave": r["wave"],
            "vuln_fixture": r["vuln_fixture"],
            "clean_fixture": r["clean_fixture"],
            "vuln_hits": r["vuln_hits"],
            "clean_hits": r["clean_hits"],
            "smoke_metadata": r.get("smoke_metadata"),
        }
        for r in passing
    ]
    (out_dir / "inventory_smoke_promote_queue.json").write_text(json.dumps(promote_queue, indent=2))

    print()
    print(f"[inventory] DONE. summary -> {out_dir/'inventory_smoke_summary.json'}")
    for s, n in sorted(by_status.items(), key=lambda kv: -kv[1]):
        print(f"  {s:24} {n}")
    print(f"  total_passes -> {len(passing)} (in promote_queue.json)")
    print(f"  duplicate ARGUMENT collisions: {len(duplicates)}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
