#!/usr/bin/env python3
"""Canonical detector runner — Wave O-B (Gap #2 closure).

Thin wrapper that routes ``--workspace`` + ``--detector`` to the underlying
scanner module and emits a normalised JSON output file (or stdout) with the
``auditooor.detector_run.v1`` schema.

Usage
-----
::

    python3 tools/run-detector.py \\
        --workspace ~/audits/base-azul \\
        --detector rust-discarded-verify-bool-scan \\
        --output /tmp/run_out.json

    # multiple detectors
    python3 tools/run-detector.py \\
        --workspace ~/audits/base-azul \\
        --detector rust-discarded-verify-bool-scan \\
        --detector rust-decode-bomb-scan \\
        --output /tmp/run_out.json

    # stdout (no --output or --output -)
    python3 tools/run-detector.py \\
        --workspace ~/audits/base-azul \\
        --detector rust-discarded-verify-bool-scan

Via Makefile::

    make detect WS=~/audits/base-azul DETECTOR=rust-discarded-verify-bool-scan
    make detect WS=~/audits/base-azul DETECTOR=rust-discarded-verify-bool-scan OUTPUT=/tmp/out.json

Output schema (``auditooor.detector_run.v1``)::

    {
      "schema_version": "auditooor.detector_run.v1",
      "detector_id": "<id>",
      "workspace": "<absolute-path>",
      "ran_at": "<iso8601>",
      "hits": [
        {"file": "rel/path/to/file.rs", "line": 42, "snippet": "...", "metadata": {...}}
      ],
      "hit_count": N
    }

Available detector IDs
----------------------
* rust-discarded-verify-bool-scan
* rust-decode-bomb-scan
* rust-from-u8-panic-on-untrusted-input-scan
* rust-non-exact-decode-trailing-bytes-scan
* rust-existence-only-cache-gate-scan
* rust-hardfork-precompile-address-mismatch-scan
* rust-host-length-cast-unbounded-alloc-scan
* rust-numeric-overflow-underflow-scan
* rust-option-iter-misclassifier-scan
* base-rust-swival-shape-scan
* rust-cache-miss-policy-scanner  (alias: rust-cache-miss-scan)
"""
from __future__ import annotations

import argparse
import importlib.util
import json
import sys
from dataclasses import asdict
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

# ---------------------------------------------------------------------------
# Detector registry: id -> tool script filename (relative to tools/)
# ---------------------------------------------------------------------------

TOOLS_DIR = Path(__file__).resolve().parent

DETECTOR_REGISTRY: dict[str, str] = {
    "rust-discarded-verify-bool-scan": "rust-discarded-verify-bool-scan.py",
    "rust-decode-bomb-scan": "rust-decode-bomb-scan.py",
    "rust-from-u8-panic-on-untrusted-input-scan": "rust-from-u8-panic-on-untrusted-input-scan.py",
    "rust-non-exact-decode-trailing-bytes-scan": "rust-non-exact-decode-trailing-bytes-scan.py",
    "rust-existence-only-cache-gate-scan": "rust-existence-only-cache-gate-scan.py",
    "rust-hardfork-precompile-address-mismatch-scan": "rust-hardfork-precompile-address-mismatch-scan.py",
    "rust-host-length-cast-unbounded-alloc-scan": "rust-host-length-cast-unbounded-alloc-scan.py",
    "rust-numeric-overflow-underflow-scan": "rust-numeric-overflow-underflow-scan.py",
    "rust-option-iter-misclassifier-scan": "rust-option-iter-misclassifier-scan.py",
    "base-rust-swival-shape-scan": "base-rust-swival-shape-scan.py",
    "rust-cache-miss-policy-scanner": "rust-cache-miss-policy-scanner.py",
    # alias
    "rust-cache-miss-scan": "rust-cache-miss-policy-scanner.py",
}

SCHEMA_VERSION = "auditooor.detector_run.v1"


def load_detector_module(detector_id: str):
    """Dynamically load a detector module by ID."""
    script = DETECTOR_REGISTRY.get(detector_id)
    if script is None:
        raise ValueError(
            f"Unknown detector id: {detector_id!r}. "
            f"Available: {sorted(DETECTOR_REGISTRY)}"
        )
    script_path = TOOLS_DIR / script
    if not script_path.exists():
        raise FileNotFoundError(
            f"Detector script not found: {script_path}"
        )
    mod_name = f"_detector_{detector_id.replace('-', '_')}"
    # Register in sys.modules BEFORE exec_module so that Python's dataclass
    # decorator can look up cls.__module__ in sys.modules (required on Py 3.14+).
    spec = importlib.util.spec_from_file_location(mod_name, script_path)
    mod = importlib.util.module_from_spec(spec)  # type: ignore[arg-type]
    sys.modules[mod_name] = mod
    try:
        spec.loader.exec_module(mod)  # type: ignore[union-attr]
    except Exception:
        sys.modules.pop(mod_name, None)
        raise
    return mod


def _row_to_hit(row: Any, workspace: Path) -> dict[str, Any]:
    """Normalise a dataclass row into the canonical hit shape."""
    if hasattr(row, "__dataclass_fields__"):
        d = asdict(row)
    elif isinstance(row, dict):
        d = dict(row)
    else:
        d = {"raw": str(row)}

    # Normalise common field names
    file_val = (
        d.pop("file", None)
        or d.pop("path", None)
        or d.pop("filepath", None)
        or ""
    )
    line_val = (
        d.pop("line", None)
        or d.pop("line_no", None)
        or d.pop("lineno", None)
        or 0
    )
    snippet_val = (
        d.pop("snippet", None)
        or d.pop("line_text", None)
        or d.pop("text", None)
        or d.pop("match", None)
        or ""
    )
    # Remaining fields go into metadata
    metadata = {k: v for k, v in d.items() if v is not None}

    return {
        "file": str(file_val),
        "line": int(line_val) if line_val else 0,
        "snippet": str(snippet_val).rstrip(),
        "metadata": metadata,
    }


def run_detector(detector_id: str, workspace: Path) -> list[dict[str, Any]]:
    """Load detector module, call run(), return normalised hits."""
    mod = load_detector_module(detector_id)
    if not hasattr(mod, "run"):
        raise AttributeError(
            f"Detector module {detector_id!r} has no run() function."
        )
    raw_rows = mod.run(workspace, [])
    hits = [_row_to_hit(r, workspace) for r in raw_rows]
    return hits


def build_output(
    detector_id: str,
    workspace: Path,
    hits: list[dict[str, Any]],
) -> dict[str, Any]:
    return {
        "schema_version": SCHEMA_VERSION,
        "detector_id": detector_id,
        "workspace": str(workspace.resolve()),
        "ran_at": datetime.now(timezone.utc).isoformat(timespec="seconds"),
        "hits": hits,
        "hit_count": len(hits),
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog="run-detector.py",
        description=(
            "Wave O-B canonical detector runner. "
            "Routes --workspace + --detector to the underlying scanner and "
            "emits auditooor.detector_run.v1 JSON."
        ),
    )
    parser.add_argument(
        "--workspace",
        required=True,
        type=Path,
        help="Absolute path to the audit workspace.",
    )
    parser.add_argument(
        "--detector",
        action="append",
        dest="detectors",
        required=True,
        metavar="DETECTOR_ID",
        help="Detector ID to run (may be repeated for multiple detectors).",
    )
    parser.add_argument(
        "--output",
        default="-",
        metavar="JSON_PATH",
        help="Path to write JSON output (default: stdout). Use '-' for stdout.",
    )
    parser.add_argument(
        "--list-detectors",
        action="store_true",
        help="Print available detector IDs and exit.",
    )
    args = parser.parse_args(argv)

    if args.list_detectors:
        for did in sorted(set(DETECTOR_REGISTRY)):
            print(did)
        return 0

    workspace = args.workspace.expanduser().resolve()
    if not workspace.is_dir():
        print(
            f"[run-detector] ERR workspace not found or not a directory: {workspace}",
            file=sys.stderr,
        )
        return 2

    detectors: list[str] = args.detectors

    # Single detector → single output document.
    # Multiple detectors → write one JSON array document with all results
    # (or multiple files if output contains {detector}).
    if len(detectors) == 1:
        detector_id = detectors[0]
        try:
            hits = run_detector(detector_id, workspace)
        except (ValueError, FileNotFoundError, AttributeError) as exc:
            print(f"[run-detector] ERR {exc}", file=sys.stderr)
            return 2

        doc = build_output(detector_id, workspace, hits)
        payload = json.dumps(doc, indent=2, sort_keys=True) + "\n"

        if args.output == "-":
            sys.stdout.write(payload)
        else:
            out_path = Path(args.output)
            out_path.parent.mkdir(parents=True, exist_ok=True)
            out_path.write_text(payload)
            print(
                f"[run-detector] {detector_id}: {len(hits)} hit(s) → {out_path}",
                file=sys.stderr,
            )
    else:
        # Fan-out: run each detector and aggregate
        all_docs: list[dict[str, Any]] = []
        for detector_id in detectors:
            try:
                hits = run_detector(detector_id, workspace)
            except (ValueError, FileNotFoundError, AttributeError) as exc:
                print(f"[run-detector] ERR {detector_id}: {exc}", file=sys.stderr)
                return 2
            all_docs.append(build_output(detector_id, workspace, hits))

        payload = json.dumps(all_docs, indent=2, sort_keys=True) + "\n"
        if args.output == "-":
            sys.stdout.write(payload)
        else:
            out_path = Path(args.output)
            out_path.parent.mkdir(parents=True, exist_ok=True)
            out_path.write_text(payload)
            total = sum(d["hit_count"] for d in all_docs)
            print(
                f"[run-detector] {len(detectors)} detectors, {total} total hit(s) → {out_path}",
                file=sys.stderr,
            )

    return 0


if __name__ == "__main__":
    sys.exit(main())
