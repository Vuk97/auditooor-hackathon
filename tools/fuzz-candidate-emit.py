#!/usr/bin/env python3
"""fuzz-candidate-emit.py — convert a fuzz-runner manifest into a deep_candidate.v1.

The existing fuzz lane lives in ``tools/fuzz-runner.sh`` which writes a
JSON manifest at ``<ws>/fuzz_runs/<run-id>/manifest.json``. This helper
provides the ``--emit-candidate`` half of the lane wire as a separate
script so the shell runner remains untouched (back-compat for V5 PR 5).

Operators / CI invoke this AFTER ``fuzz-runner.sh`` completes:

    tools/fuzz-candidate-emit.py \
        --workspace <ws> \
        --manifest <ws>/fuzz_runs/<run>/manifest.json

The emitter is permissive about manifest shape — it tolerates missing
keys and falls back to advisory-floor defaults rather than raising.
"""

from __future__ import annotations

import argparse
import importlib.util
import json
import sys
from pathlib import Path
from typing import Any, Dict, List, Optional


def _load_deep_candidate_lib() -> Optional[Any]:
    spec_path = Path(__file__).resolve().parent / "lib" / "deep_candidate.py"
    if not spec_path.is_file():
        return None
    spec = importlib.util.spec_from_file_location("_deep_candidate_lib_fuzz", spec_path)
    if spec is None or spec.loader is None:
        return None
    module = importlib.util.module_from_spec(spec)
    sys.modules.setdefault("_deep_candidate_lib_fuzz", module)
    spec.loader.exec_module(module)
    return module


def _failures_from_manifest(manifest: Dict[str, Any]) -> List[Dict[str, Any]]:
    """Pick out failed invariants from a fuzz manifest, tolerantly."""
    failures = manifest.get("failures") or manifest.get("failed_invariants") or []
    if isinstance(failures, dict):
        failures = list(failures.values())
    if not isinstance(failures, list):
        return []
    return [f for f in failures if isinstance(f, dict)]


def emit(workspace: Path, manifest_path: Path) -> int:
    lib = _load_deep_candidate_lib()
    if lib is None:
        print("[fuzz-candidate-emit] ERR deep_candidate lib not found", file=sys.stderr)
        return 2

    try:
        manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        print(f"[fuzz-candidate-emit] ERR cannot parse manifest: {exc}",
              file=sys.stderr)
        return 2

    failures = _failures_from_manifest(manifest)
    if not failures:
        print(
            "[fuzz-candidate-emit] no failed invariants in manifest; nothing to emit",
            file=sys.stderr,
        )
        return 0

    count = 0
    for idx, failure in enumerate(failures):
        invariant = str(failure.get("invariant") or failure.get("name") or f"failure-{idx}")
        contract = str(failure.get("contract") or "unknown")
        path = failure.get("path") or failure.get("file") or "unknown.t.sol"
        seed = failure.get("seed") or failure.get("counterexample") or {}
        replayable = bool(seed)
        promotion = "investigate" if replayable else "hold"
        repro = (
            f"forge test --match-test {invariant} -vv "
            f"(seed in lane_payload.seed)"
            if replayable
            else (
                "no replayable seed captured in fuzz manifest; rerun "
                "fuzz-runner.sh with seed-collection enabled"
            )
        )
        doc = lib.build_candidate(
            lane="fuzz",
            candidate_id=f"fuzz.{contract}.{invariant}.{idx}",
            files=[str(path)],
            claim=(
                f"Foundry fuzz invariant `{invariant}` failed against "
                f"{contract}; advisory until replayed deterministically."
            ),
            trigger=(
                "Foundry fuzzer found an input vector that violates the "
                "invariant; exact actor sequence is in lane_payload.seed."
            ),
            impact=(
                "Invariant failure does not by itself prove an exploit; "
                "promotion requires a replay test in the engagement repo "
                "and confirmation that the failing path is production-reachable."
            ),
            reproduction=repro,
            confidence="low",
            promotion_status=promotion,
            blocking_questions=[
                "Has the failing seed been replayed in the engagement Foundry repo?",
                "Does the failing call sequence touch a production entrypoint?",
                "Is the invariant well-formed, or does it encode an unintended assumption?",
            ],
            tool="fuzz-candidate-emit.py",
            workspace=workspace,
            lane_payload={
                "invariant": invariant,
                "contract": contract,
                "manifest": str(manifest_path),
                "seed": seed,
            },
        )
        out = lib.write_candidate(doc, workspace=workspace)
        print(f"[fuzz-candidate-emit] EMIT {out}", file=sys.stderr)
        count += 1
    return 0 if count else 1


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(
        description=(
            "Convert a fuzz-runner.sh manifest into deep_candidate.v1 JSON "
            "files under <workspace>/deep_candidates/."
        ),
    )
    p.add_argument("--workspace", required=True, type=Path,
                   help="Engagement workspace (deep_candidates/ written under here).")
    p.add_argument("--manifest", required=True, type=Path,
                   help="fuzz_runs/<run-id>/manifest.json produced by fuzz-runner.sh.")
    args = p.parse_args(argv)
    return emit(args.workspace, args.manifest)


if __name__ == "__main__":
    sys.exit(main())
