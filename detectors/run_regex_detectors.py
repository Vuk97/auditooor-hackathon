#!/usr/bin/env python3
"""run_regex_detectors.py — runner for the regex-API wave* detectors.

Sister utility to ``detectors/run_custom.py`` (Slither AbstractDetector path).
Discovers every ``detectors/wave*/<mod>.py`` that exports a regex-style
``scan(source: str, file_path: str) -> list[Finding]`` callable, walks
``.sol`` files under a target directory, runs each detector, aggregates
findings, and writes:

    * human-readable stdout summary
    * machine-readable JSON manifest at
      ``<workspace>/.audit_logs/regex_detectors_manifest.json``

L28-B fix
---------
The wave17 detectors shipped 2026-05-08 (v4_hook_take_before_pricing_state_mutation
and 5 siblings) use a regex ``scan()`` API rather than Slither's
``AbstractDetector`` ABC, so ``run_custom.py``'s class-discovery loop misses
them entirely. Without this runner, ``make audit WS=<ws>`` doesn't fire the
new patterns — exactly the L28-B failure mode codified as
"documentation ≠ enforcement". This script is the missing enforcement
edge.

Stdlib only. No Slither dependency, so it imports cleanly even on hosts
where ``slither-analyzer`` is not installed.

Usage
-----
    python3 detectors/run_regex_detectors.py <target-dir> [options]

Options:
    --detector <name>   Run only the given detector (matches DETECTOR_NAME or stem)
    --output <path>     Override JSON manifest path (default: <ws>/.audit_logs/regex_detectors_manifest.json)
    --workspace <path>  Workspace root for manifest placement (default: target-dir)
    --json-only         Suppress per-finding stdout lines (manifest still written)
    --no-manifest       Skip manifest write (stdout only)

Output manifest schema
----------------------
    {
      "schema": "auditooor.regex_detectors_manifest.v1",
      "target": "<absolute path>",
      "workspace": "<absolute path>",
      "detectors": ["<DETECTOR_NAME>", ...],
      "files_scanned": <int>,
      "findings": [
        {
          "detector": "<DETECTOR_NAME>",
          "severity": "<High|Medium|Low|Informational|Unknown>",
          "file": "<absolute path>",
          "line": <int>,
          "message": "<text>",
          "function": "<name|null>",
          "fp_guardrails_passed": true
        },
        ...
      ],
      "per_detector_counts": { "<DETECTOR_NAME>": <int>, ... }
    }
"""

from __future__ import annotations

import argparse
import importlib.util
import inspect
import json
import sys
import time
from dataclasses import asdict, is_dataclass
from pathlib import Path
from typing import Any, Iterable

HERE = Path(__file__).resolve().parent
DETECTORS_ROOT = HERE


# Vendored / generated paths to skip when walking .sol files. Mirrors
# run_custom.py's VENDORED_MARKERS so the two runners report on the same
# in-scope surface.
_VENDOR_PARTS = {
    "node_modules",
    "lib",
    "vendor",
    "out",
    "cache",
    "broadcast",
    "forge-std",
}


# ---------------------------------------------------------------------------
# Detector discovery
# ---------------------------------------------------------------------------


def _looks_like_regex_scan(mod: Any) -> bool:
    """True iff the module exports a top-level ``scan(source, file_path)``
    callable. We accept the loose form of any ``scan`` whose first two
    positional params are named ``source`` and ``file_path`` (or where the
    signature has ``>= 1`` positional param — defensive for older shapes)."""
    fn = getattr(mod, "scan", None)
    if not callable(fn):
        return False
    try:
        sig = inspect.signature(fn)
    except (TypeError, ValueError):
        # builtin / C function with no introspectable signature → accept
        # if it's at least callable; downstream try/except will catch real
        # mismatches.
        return True
    params = list(sig.parameters.values())
    if not params:
        return False
    # First positional must be the source string. We don't enforce the name
    # strictly — wave17 names it `source`, future waves may rename to
    # `text` etc.
    return True


def discover_detectors(detectors_root: Path = DETECTORS_ROOT,
                       name_filter: str | None = None) -> list[tuple[str, Any, Path]]:
    """Return list of (DETECTOR_NAME, module, source-path) for every
    discovered regex-API detector under ``detectors_root/wave*/``.

    Top-level files (``run_*.py``, ``_*.py``) are skipped. Subdirs whose
    leaf name starts with ``_`` are also skipped (e.g.
    ``wave17/_quarantine_*``).
    """
    out: list[tuple[str, Any, Path]] = []
    seen_names: set[str] = set()
    py_files = sorted(detectors_root.glob("wave*/*.py"))
    for py_file in py_files:
        # Skip private / quarantine subdirs and underscore-prefixed files.
        rel_parts = py_file.relative_to(detectors_root).parts
        if any(part.startswith("_") for part in rel_parts):
            continue
        if py_file.name.startswith("_"):
            continue
        # Stable, unique module name to avoid collisions across waves.
        mod_name = "regex_det." + "_".join(rel_parts).replace(".py", "")
        spec = importlib.util.spec_from_file_location(mod_name, py_file)
        if spec is None or spec.loader is None:
            continue
        mod = importlib.util.module_from_spec(spec)
        # Register in sys.modules BEFORE exec_module so @dataclass /
        # other decorators that consult sys.modules[mod.__module__] don't
        # blow up with NoneType (Python 3.12+ behavior).
        sys.modules[mod_name] = mod
        try:
            spec.loader.exec_module(mod)
        except Exception:
            # Some wave* files import slither-only helpers at module level
            # (run_custom.py path). Those will fail to import here — skip
            # them silently; this runner only cares about regex-API ones.
            sys.modules.pop(mod_name, None)
            continue
        if not _looks_like_regex_scan(mod):
            continue
        det_name = getattr(mod, "DETECTOR_NAME", py_file.stem)
        if name_filter and name_filter not in (det_name, py_file.stem):
            continue
        if det_name in seen_names:
            # Two files exporting the same DETECTOR_NAME — keep first; emit
            # to stderr so the operator can clean up later.
            print(f"[regex-runner] WARN duplicate DETECTOR_NAME={det_name!r} "
                  f"(skipping {py_file})", file=sys.stderr)
            continue
        seen_names.add(det_name)
        out.append((det_name, mod, py_file))
    return out


# ---------------------------------------------------------------------------
# Source-file walking
# ---------------------------------------------------------------------------


def iter_solidity_sources(target: Path) -> Iterable[Path]:
    """Yield every non-vendored .sol file under ``target``."""
    if target.is_file() and target.suffix == ".sol":
        yield target
        return
    if not target.is_dir():
        return
    for p in target.rglob("*.sol"):
        if any(part in _VENDOR_PARTS for part in p.parts):
            continue
        yield p


# ---------------------------------------------------------------------------
# Finding normalization
# ---------------------------------------------------------------------------


def _finding_to_dict(f: Any, *, fallback_detector: str) -> dict[str, Any]:
    """Normalize a Finding (dataclass / dict / namedtuple-ish) to the manifest
    shape. Robust to older shapes that don't carry ``severity`` or
    ``function``."""
    if is_dataclass(f):
        d = asdict(f)
    elif isinstance(f, dict):
        d = dict(f)
    else:
        # Best-effort: pull common attributes
        d = {}
        for attr in ("detector", "file", "line", "severity", "message", "function"):
            if hasattr(f, attr):
                d[attr] = getattr(f, attr)
    return {
        "detector": d.get("detector") or fallback_detector,
        "severity": d.get("severity") or "Unknown",
        "file": d.get("file") or "<unknown>",
        "line": int(d.get("line") or 0),
        "message": d.get("message") or "",
        "function": d.get("function"),
        # FP guardrails are detector-internal in the wave17 design; we treat
        # any returned finding as having passed the in-detector guards.
        "fp_guardrails_passed": True,
    }


# ---------------------------------------------------------------------------
# Driver
# ---------------------------------------------------------------------------


def run(target: Path,
        workspace: Path,
        manifest_path: Path | None,
        name_filter: str | None,
        json_only: bool,
        no_manifest: bool,
        detectors_root: Path = DETECTORS_ROOT) -> int:
    detectors = discover_detectors(detectors_root, name_filter=name_filter)
    if not detectors:
        msg = "no regex-API detectors discovered"
        if name_filter:
            msg += f" (filter={name_filter!r})"
        print(f"[regex-runner] {msg}", file=sys.stderr)
        # Empty discovery is not a hard error — still write a stub manifest
        # so downstream "did this stage run?" checks see a fresh artifact.

    if not json_only:
        print(f"[regex-runner] target={target}")
        print(f"[regex-runner] detectors loaded: {len(detectors)}")
        for det_name, _mod, src in detectors:
            print(f"  - {det_name}  ({src.relative_to(detectors_root.parent)})")

    files = list(iter_solidity_sources(target))
    if not json_only:
        print(f"[regex-runner] sol files to scan: {len(files)}")

    findings_out: list[dict[str, Any]] = []
    per_detector_counts: dict[str, int] = {det_name: 0 for det_name, _, _ in detectors}
    t0 = time.time()
    for sol in files:
        try:
            text = sol.read_text(encoding="utf-8", errors="replace")
        except Exception as e:
            print(f"[regex-runner] WARN cannot read {sol}: {e}", file=sys.stderr)
            continue
        for det_name, mod, _src in detectors:
            try:
                results = mod.scan(text, str(sol)) or []
            except Exception as e:
                print(f"[regex-runner] WARN {det_name} raised on {sol}: {e}",
                      file=sys.stderr)
                continue
            for r in results:
                d = _finding_to_dict(r, fallback_detector=det_name)
                findings_out.append(d)
                per_detector_counts[det_name] = per_detector_counts.get(det_name, 0) + 1
    elapsed = time.time() - t0

    if not json_only:
        print()
        for d in findings_out:
            sev = d.get("severity", "Unknown")
            line_loc = f"{d.get('file')}:{d.get('line')}"
            print(f"  [{sev}] {d.get('detector')}: {d.get('message','')[:200]}  ({line_loc})")
        print()
        print(f"[regex-runner] total hits: {len(findings_out)}  ({elapsed:.1f}s)")
        if per_detector_counts:
            print("[regex-runner] per-detector counts:")
            for name, count in sorted(per_detector_counts.items(), key=lambda x: (-x[1], x[0])):
                print(f"  {count:5d}  {name}")

    if no_manifest:
        return 0

    # Write JSON manifest
    if manifest_path is None:
        manifest_path = workspace / ".audit_logs" / "regex_detectors_manifest.json"
    manifest = {
        "schema": "auditooor.regex_detectors_manifest.v1",
        "target": str(target.resolve()),
        "workspace": str(workspace.resolve()),
        "detectors": [name for name, _, _ in detectors],
        "files_scanned": len(files),
        "elapsed_seconds": round(elapsed, 3),
        "findings": findings_out,
        "per_detector_counts": per_detector_counts,
    }
    try:
        manifest_path.parent.mkdir(parents=True, exist_ok=True)
        manifest_path.write_text(json.dumps(manifest, indent=2, sort_keys=True),
                                 encoding="utf-8")
        if not json_only:
            print(f"[regex-runner] wrote manifest → {manifest_path}")
    except Exception as e:
        print(f"[regex-runner] ERR writing manifest: {e}", file=sys.stderr)
        return 1
    return 0


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(
        prog="run_regex_detectors.py",
        description="Run regex-API wave* detectors against a Solidity tree.",
    )
    ap.add_argument("target", help="Target directory (or single .sol file)")
    ap.add_argument("--workspace", default=None,
                    help="Workspace root for manifest placement (default: target)")
    ap.add_argument("--detector", default=None,
                    help="Run only the named detector (matches DETECTOR_NAME or stem)")
    ap.add_argument("--output", default=None,
                    help="Override JSON manifest path "
                         "(default: <workspace>/.audit_logs/regex_detectors_manifest.json)")
    ap.add_argument("--json-only", action="store_true",
                    help="Suppress per-finding stdout lines (manifest still written)")
    ap.add_argument("--no-manifest", action="store_true",
                    help="Skip JSON manifest write (stdout only)")
    args = ap.parse_args(argv)

    target = Path(args.target).resolve()
    workspace = Path(args.workspace).resolve() if args.workspace else target
    if target.is_file():
        # If a single .sol file was passed without --workspace, anchor at parent.
        if args.workspace is None:
            workspace = target.parent
    manifest_path = Path(args.output).resolve() if args.output else None
    return run(
        target=target,
        workspace=workspace,
        manifest_path=manifest_path,
        name_filter=args.detector,
        json_only=args.json_only,
        no_manifest=args.no_manifest,
    )


if __name__ == "__main__":
    sys.exit(main())
