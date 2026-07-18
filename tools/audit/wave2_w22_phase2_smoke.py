"""
Wave-3 W2.2 Phase-2 smoke driver.

Scans a workspace's source tree against the detector roster loaded by
`tools/audit/wave2_w22_detector_loader.py` and emits a JSON summary
counting hits per detector_id. The driver is intentionally simple: it
treats each detector's `shape_literal` as a substring match (or its
canonical attack-class keyword as a fallback) and counts file matches.

The driver exists for smoke validation only - it is NOT the load-bearing
detector runner. The production runner (per spec section 8) will be
`tools/audit/run-autogen-detectors.py` shipped by the Phase-1
implementation lane. This smoke driver answers one question: when
Phase-2 is enabled, does the broader detector roster fire on a real
workspace at a count distinct from Phase-1 alone?

Usage:
  python3 tools/audit/wave2_w22_phase2_smoke.py \\
    --workspace /Users/wolf/audits/centrifuge-v3 \\
    --output /tmp/smoke.json

Env knobs (same as the loader):
  AUDITOOOR_W22_PHASE1_ENABLED, AUDITOOOR_W22_PHASE2_ENABLED.

Reference docs:
  - docs/WAVE2_W22_DETECTOR_AUTOGEN_SPEC_2026-05-16.md
  - docs/WAVE3_W22_PHASE2_ENABLE_2026-05-16.md
"""

from __future__ import annotations

import argparse
import json
import os
import sys
from pathlib import Path
from typing import Any

# Make the loader importable regardless of cwd.
_THIS_DIR = Path(__file__).resolve().parent
_REPO_ROOT = _THIS_DIR.parents[1]
if str(_REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(_REPO_ROOT))

from tools.audit.wave2_w22_detector_loader import (  # noqa: E402
    PHASE1_ENV_FLAG,
    PHASE2_ENV_FLAG,
    load_active_detectors,
    loader_status,
)

LANGUAGE_EXTENSIONS: dict[str, tuple[str, ...]] = {
    "solidity": (".sol",),
    "vyper": (".vy",),
    "go": (".go",),
    "rust": (".rs",),
    "circom": (".circom",),
}

# Excluded path fragments to skip noise (tests, build artifacts, node_modules).
EXCLUDED_PATH_FRAGMENTS = (
    "/node_modules/",
    "/.git/",
    "/dist/",
    "/build/",
    "/out/",
    "/.foundry/",
    "/cache/",
)


def _shape_for_detector(detector: dict[str, Any]) -> str | None:
    """Resolve the substring literal a detector wants to match.

    Priority: phase-2 `shape_literal` field, then a fallback keyword
    derived from the detector_id suffix or attack_class.
    """
    literal = detector.get("shape_literal")
    if isinstance(literal, str) and literal.strip():
        return literal
    # Fallback: derive from detector_id (Phase-1 detectors do not carry
    # shape_literal in their preview roster). Use the rightmost
    # significant token as the substring.
    det_id = detector.get("detector_id", "")
    if "reentrancy" in det_id:
        return "nonReentrant" if detector.get("language") == "solidity" else "@nonreentrant"
    if "panic" in det_id:
        return "panic"
    if "unconstrained" in det_id:
        return "<--"
    if "validate_basic" in det_id.lower():
        return "ValidateBasic"
    if "mempool" in det_id.lower():
        return "Mempool"
    if "evidence_pool" in det_id.lower():
        return "EvidencePool"
    if "p2p" in det_id.lower():
        return "p2p"
    if "groups_module" in det_id.lower():
        return "Group"
    if "zksolc" in det_id.lower() or "compile" in det_id.lower():
        return "compile"
    if "op_geth" in det_id.lower() or "invalid_payload" in det_id.lower():
        return "payload"
    return detector.get("attack_class")


def _iter_workspace_files(
    workspace: Path, extensions: tuple[str, ...]
) -> list[Path]:
    """Walk workspace/src (preferred) or workspace root for matching files."""
    roots: list[Path] = []
    for candidate in (workspace / "src", workspace / "contracts", workspace):
        if candidate.is_dir():
            roots.append(candidate)
            break
    if not roots:
        return []
    out: list[Path] = []
    for root in roots:
        for path in root.rglob("*"):
            if not path.is_file():
                continue
            if not any(str(path).endswith(ext) for ext in extensions):
                continue
            if any(frag in str(path) for frag in EXCLUDED_PATH_FRAGMENTS):
                continue
            out.append(path)
    return out


def _count_hits_for_detector(
    detector: dict[str, Any], workspace: Path
) -> int:
    language = detector.get("language")
    if language not in LANGUAGE_EXTENSIONS:
        return 0
    shape = _shape_for_detector(detector)
    if not shape:
        return 0
    files = _iter_workspace_files(workspace, LANGUAGE_EXTENSIONS[language])
    hit_count = 0
    for path in files:
        try:
            body = path.read_text(encoding="utf-8", errors="ignore")
        except OSError:
            continue
        if shape in body:
            hit_count += 1
    return hit_count


def run_smoke(workspace: Path, env: dict[str, str] | None = None) -> dict[str, Any]:
    """Run the smoke pass and emit a structured result dict."""
    env_src = env if env is not None else dict(os.environ)
    status = loader_status(env_src)
    detectors = load_active_detectors(env_src)
    per_detector: list[dict[str, Any]] = []
    total_hits = 0
    for det in detectors:
        hit = _count_hits_for_detector(det, workspace)
        per_detector.append(
            {
                "detector_id": det.get("detector_id"),
                "language": det.get("language"),
                "attack_class": det.get("attack_class"),
                "shape_literal": _shape_for_detector(det),
                "severity_floor": det.get("severity_floor"),
                "phase": det.get("rollout_phase", 1),
                "hit_files": hit,
            }
        )
        total_hits += hit
    return {
        "schema": "auditooor.wave2_w22_phase2_smoke.v1",
        "workspace": str(workspace),
        "workspace_exists": workspace.is_dir(),
        "loader_status": status,
        "total_hit_files": total_hits,
        "detector_count_evaluated": len(detectors),
        "per_detector_hits": per_detector,
    }


def main() -> int:
    parser = argparse.ArgumentParser(description="W2.2 Phase-2 smoke driver")
    parser.add_argument("--workspace", required=True, help="Path to the workspace root")
    parser.add_argument("--output", default="-", help="Output JSON path (- for stdout)")
    parser.add_argument(
        "--strict-empty",
        action="store_true",
        help="Exit non-zero if the loader is fully OFF (no detectors evaluated)",
    )
    args = parser.parse_args()
    workspace = Path(args.workspace).expanduser().resolve()
    result = run_smoke(workspace)
    text = json.dumps(result, indent=2, sort_keys=True)
    if args.output == "-":
        sys.stdout.write(text + "\n")
    else:
        Path(args.output).write_text(text + "\n", encoding="utf-8")
        sys.stdout.write(f"[wave2-w22-phase2-smoke] wrote {args.output}\n")
    if args.strict_empty and result["detector_count_evaluated"] == 0:
        sys.stderr.write(
            f"[wave2-w22-phase2-smoke] WARNING: loader OFF; "
            f"set {PHASE1_ENV_FLAG}=1 (and optionally {PHASE2_ENV_FLAG}=1)\n"
        )
        return 2
    return 0


if __name__ == "__main__":
    sys.exit(main())
