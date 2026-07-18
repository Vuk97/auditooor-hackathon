#!/usr/bin/env python3
"""Detector registry completeness check (L28-B discipline enforcement).

Diffs documented patterns in reference/patterns.dsl* YAML files against
runnable detector surfaces. Solidity/Python detectors are .py files
discoverable by detectors/run_custom.py (wave*/*.py glob). Language-native
DSL runners may also satisfy completeness when they are wired into the base
scan path and own that backend's pattern rows. Fails closed when STRICT=1
and documented patterns have no corresponding runnable detector.

Whitelist exceptions: patterns/.unwired_allowlist (one pattern id per
line; comments prefixed with #).

Output (one row per documented pattern):
  TSV: pattern_name<TAB>documented_at<TAB>wired_status<TAB>runner_path

Summary line: "<N> documented, <M> wired, <K> unwired"

Exit codes:
  0  All documented patterns are wired (or allowlisted).
  1  STRICT=1 and at least one undocumented/unwired pattern found.
  2  Usage error.

Usage:
  python3 tools/detector-registry-completeness-check.py [--strict] [--tsv] [--repo <path>]
  STRICT=1 python3 tools/detector-registry-completeness-check.py
"""

from __future__ import annotations

import argparse
import os
import sys
from pathlib import Path
from typing import NamedTuple


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _find_repo_root(start: Path | None = None) -> Path:
    """Walk up from *start* to find the repo root (contains Makefile)."""
    here = (start or Path(__file__)).resolve()
    for p in [here, *here.parents]:
        if (p / "Makefile").is_file() and (p / "detectors").is_dir():
            return p
    # Fallback: two levels up from this file
    return here.parent.parent


def _load_allowlist(repo: Path) -> set[str]:
    """Return the set of allowlisted pattern IDs from patterns/.unwired_allowlist."""
    path = repo / "patterns" / ".unwired_allowlist"
    if not path.is_file():
        return set()
    ids: set[str] = set()
    for line in path.read_text(encoding="utf-8").splitlines():
        stripped = line.strip()
        if stripped and not stripped.startswith("#"):
            ids.add(stripped)
    return ids


def _collect_documented_patterns(repo: Path) -> list[tuple[str, str]]:
    """Return list of (pattern_id, documented_at_path) for all YAML patterns.

    Scans reference/patterns.dsl* directories (matching the same directories
    that pattern-compile.py and vault populate).  Pattern IDs are derived from
    YAML filenames (stem), matching the ARGUMENT convention in detectors.
    """
    results: list[tuple[str, str]] = []
    ref_dir = repo / "reference"
    if not ref_dir.is_dir():
        return results

    # Collect all patterns.dsl* directories (main + round-suffixed)
    dsl_dirs = [d for d in ref_dir.iterdir()
                if d.is_dir() and d.name.startswith("patterns.dsl")]

    for dsl_dir in sorted(dsl_dirs):
        for yaml_path in sorted(dsl_dir.glob("*.yaml")):
            # Skip files in subdirectories (held, quarantine, etc.)
            pattern_id = yaml_path.stem  # e.g. "dust-redeem-floor-rounds-to-zero"
            rel = str(yaml_path.relative_to(repo))
            results.append((pattern_id, rel))

    return results


def _collect_wired_detectors(repo: Path) -> dict[str, str]:
    """Return dict pattern_id -> runner_path for all wired detector surfaces.

    Python discovery rule: same glob as detectors/run_custom.py _detector_py_files:
      detectors/*.py  +  detectors/wave*/*.py
    (excludes wave_graveyard / quarantine / dunder files).

    The ARGUMENT attribute in the detector class is canonical; filename stem
    is the fallback (hyphens = underscores).

    Native-runner rule: a backend-specific DSL row is wired when its native
    runner exists and is present in the base workspace scan orchestrator.
    """
    result: dict[str, str] = {}
    result.update(_collect_run_custom_detectors(repo))
    for pattern_id, runner_path in _collect_native_runner_patterns(repo).items():
        result.setdefault(pattern_id, runner_path)
    return result


def _collect_run_custom_detectors(repo: Path) -> dict[str, str]:
    """Return dict pattern_id -> detector .py path for run_custom detectors."""
    detectors_dir = repo / "detectors"
    if not detectors_dir.is_dir():
        return {}

    py_files: list[Path] = (
        sorted(detectors_dir.glob("*.py"))
        + sorted(detectors_dir.glob("wave*/*.py"))
    )

    result: dict[str, str] = {}

    for py_path in py_files:
        # Skip dunder / private files and the runner itself
        if py_path.name.startswith("_") or py_path.name == "run_custom.py":
            continue
        # Skip quarantine / graveyard directories
        parts = py_path.parts
        if any(seg.startswith("_quarantine") or seg == "wave_graveyard"
               for seg in parts):
            continue

        rel = str(py_path.relative_to(repo))

        # Try to extract ARGUMENT from source (cheap regex; no import needed)
        argument = _extract_argument(py_path)
        if argument:
            result[argument] = rel
        else:
            # Fallback: stem with underscores → hyphens
            stem_as_arg = py_path.stem.replace("_", "-")
            result[stem_as_arg] = rel

    return result


def _collect_native_runner_patterns(repo: Path) -> dict[str, str]:
    """Return pattern_id -> native runner path for base-scan-wired DSL rows.

    Today this recognizes Cosmos DSL rows (`backend: cosmos`) owned by
    tools/cosmos-detector-runner.py. The runner is counted only when the repo
    has the runner and the base workspace scan orchestrator invokes it; this
    keeps fixture-only/documentation-only DSL rows from being marked wired.
    """
    native_backends = {
        "cosmos": {
            "runner": repo / "tools" / "cosmos-detector-runner.py",
            "runner_rel": "tools/cosmos-detector-runner.py",
            "base_scan": repo / "tools" / "workspace-scan-orchestrator.py",
            "base_scan_tokens": ("COSMOS_DETECT", "cosmos-detector-runner.py"),
        },
    }

    active_backends: dict[str, str] = {}
    for backend, cfg in native_backends.items():
        runner = cfg["runner"]
        base_scan = cfg["base_scan"]
        if not runner.is_file() or not base_scan.is_file():
            continue
        try:
            base_scan_text = base_scan.read_text(encoding="utf-8", errors="replace")
        except OSError:
            continue
        if not all(token in base_scan_text for token in cfg["base_scan_tokens"]):
            continue
        active_backends[backend] = cfg["runner_rel"]

    if not active_backends:
        return {}

    result: dict[str, str] = {}
    for pattern_id, documented_at in _collect_documented_patterns(repo):
        yaml_path = repo / documented_at
        spec = _extract_pattern_backend(yaml_path)
        if not spec:
            continue
        declared_pattern, backend = spec
        runner_rel = active_backends.get(backend)
        if not runner_rel:
            continue
        # Completeness rows are keyed by filename stem. The native runner
        # executes the DSL `pattern:` field, so require agreement when present.
        if declared_pattern and declared_pattern != pattern_id:
            continue
        result[pattern_id] = runner_rel
    return result


def _extract_argument(py_path: Path) -> str | None:
    """Extract ARGUMENT = "..." from detector source without importing it."""
    import re
    try:
        text = py_path.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return None
    m = re.search(r'ARGUMENT\s*=\s*["\']([^"\']+)["\']', text)
    return m.group(1) if m else None


def _extract_pattern_backend(yaml_path: Path) -> tuple[str | None, str] | None:
    """Extract top-level `pattern` and `backend` scalars from a DSL YAML file.

    This intentionally handles only the simple top-level scalar shape needed
    for runner ownership. It avoids importing PyYAML in this docs/status gate.
    """
    try:
        text = yaml_path.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return None

    pattern: str | None = None
    backend: str | None = None
    for line in text.splitlines():
        stripped = line.strip()
        if not stripped or stripped.startswith("#") or line[:1].isspace():
            continue
        key, sep, value = stripped.partition(":")
        if sep != ":":
            continue
        key = key.strip()
        value = _strip_inline_yaml_comment(value).strip()
        if key == "pattern":
            pattern = _unquote_scalar(value)
        elif key == "backend":
            backend = _unquote_scalar(value).lower()
        if backend and pattern is not None:
            break
    if not backend:
        return None
    return (pattern, backend)


def _strip_inline_yaml_comment(value: str) -> str:
    """Strip comments from a simple YAML scalar while respecting quotes."""
    in_single = False
    in_double = False
    out: list[str] = []
    for ch in value:
        if ch == "'" and not in_double:
            in_single = not in_single
        elif ch == '"' and not in_single:
            in_double = not in_double
        elif ch == "#" and not in_single and not in_double:
            break
        out.append(ch)
    return "".join(out)


def _unquote_scalar(value: str) -> str:
    value = value.strip()
    if len(value) >= 2 and value[0] == value[-1] and value[0] in ("'", '"'):
        return value[1:-1]
    return value


# ---------------------------------------------------------------------------
# Report row
# ---------------------------------------------------------------------------

class PatternRow(NamedTuple):
    pattern_id: str
    documented_at: str
    wired_status: str   # "wired" | "unwired" | "allowlisted"
    runner_path: str    # path to .py file, or "" if unwired


# ---------------------------------------------------------------------------
# Main logic
# ---------------------------------------------------------------------------

def run_check(repo: Path, strict: bool, tsv: bool) -> int:
    """Execute the check. Returns exit code."""
    allowlist = _load_allowlist(repo)
    documented = _collect_documented_patterns(repo)
    wired = _collect_wired_detectors(repo)

    rows: list[PatternRow] = []
    unwired_non_allowlisted: list[str] = []

    for pattern_id, documented_at in documented:
        if pattern_id in wired:
            rows.append(PatternRow(
                pattern_id=pattern_id,
                documented_at=documented_at,
                wired_status="wired",
                runner_path=wired[pattern_id],
            ))
        elif pattern_id in allowlist:
            rows.append(PatternRow(
                pattern_id=pattern_id,
                documented_at=documented_at,
                wired_status="allowlisted",
                runner_path="",
            ))
        else:
            rows.append(PatternRow(
                pattern_id=pattern_id,
                documented_at=documented_at,
                wired_status="unwired",
                runner_path="",
            ))
            unwired_non_allowlisted.append(pattern_id)

    # --- Output ---
    if tsv:
        print("pattern_name\tdocumented_at\twired_status\trunner_path")
        for r in rows:
            print(f"{r.pattern_id}\t{r.documented_at}\t{r.wired_status}\t{r.runner_path}")
    else:
        # Summary-only mode: only print unwired patterns
        for r in rows:
            if r.wired_status == "unwired":
                print(f"[unwired] {r.pattern_id}  (documented at {r.documented_at})")

    n_documented = len(rows)
    n_wired = sum(1 for r in rows if r.wired_status == "wired")
    n_allowlisted = sum(1 for r in rows if r.wired_status == "allowlisted")
    n_unwired = len(unwired_non_allowlisted)

    summary = (
        f"{n_documented} documented, {n_wired} wired, "
        f"{n_allowlisted} allowlisted, {n_unwired} unwired"
    )
    print(f"[detector-registry-completeness] {summary}")

    if strict and n_unwired > 0:
        print(
            f"[detector-registry-completeness] FAIL — "
            f"{n_unwired} documented pattern(s) not wired into any runner"
        )
        return 1

    if not strict and n_unwired > 0:
        print(
            f"[detector-registry-completeness] WARN — "
            f"{n_unwired} documented pattern(s) not wired (run with STRICT=1 to fail)"
        )

    if n_unwired == 0:
        print("[detector-registry-completeness] OK")

    return 0


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Diff documented patterns against wired detectors.",
    )
    parser.add_argument(
        "--strict",
        action="store_true",
        default=(os.environ.get("STRICT", "") == "1"),
        help="Fail (exit 1) when any documented pattern is unwired.",
    )
    parser.add_argument(
        "--tsv",
        action="store_true",
        help="Emit full TSV table instead of summary-only.",
    )
    parser.add_argument(
        "--repo",
        type=Path,
        default=None,
        help="Repo root (auto-detected when omitted).",
    )
    args = parser.parse_args(argv)

    repo = args.repo if args.repo else _find_repo_root()
    return run_check(repo=repo, strict=args.strict, tsv=args.tsv)


if __name__ == "__main__":
    sys.exit(main())
