#!/usr/bin/env python3
"""agent-recall-replay.py - Replay agent-found behaviors and measure detectorized-vs-not split.

For each agent-found behavior recorded by agent-artifact-miner.py, this tool
determines whether a detector would have caught it (detectorized) or not
(recall gap). It emits a JSON report with:

  - total agent-found behaviors
  - detectorized count (scanner would have fired)
  - non-detectorized count (recall gap)
  - recall_rate (detectorized / total, 0.0 if total == 0)
  - a bounded list of recall-gap behaviors with a durable_route

IMPORTANT - attention and ranking metric only:
  Recall is an attention/ranking metric that helps prioritize which behaviors
  to convert into detectors. It is NEVER a proof signal. A behavior appearing
  in the recall-gap list does not imply it is exploitable, fileable, or even
  a real bug. Do not use recall improvement as filing evidence.

Classification reuses the logic from tools/base-critical-hunt.py
(_has_detector_hit / AGENT_HINT_RE / DETECTOR_HINT_RE) rather than
reinventing it. See that module for authoritative semantics.

Schema: auditooor.agent_recall_replay.v1

Usage:
    python3 tools/agent-recall-replay.py --workspace ~/audits/<project> --json
    python3 tools/agent-recall-replay.py --workspace ~/audits/<project> \\
        --out reports/agent_recall_replay.json
"""

from __future__ import annotations

import argparse
import hashlib
import importlib.util
import json
import re
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

SCHEMA_VERSION = "auditooor.agent_recall_replay.v1"
MAX_GAP_ROWS = 50  # bounded list - never explode output

# ---------------------------------------------------------------------------
# Regex patterns mirrored from base-critical-hunt.py
# (compose read-only; do not edit the original)
# ---------------------------------------------------------------------------

# Signal that a behavior was surfaced by an agent (not a scanner)
AGENT_HINT_RE = re.compile(
    r"\b(agent|claude|kimi|minimax|codex|source[- ]reader|source[- ]reading|llm)\b",
    re.IGNORECASE,
)

# Signal that a scanner/detector has already fired on this behavior
DETECTOR_HINT_RE = re.compile(
    r"\b(detector|scanner|semgrep|slither|cargo audit|scan[-_ ]rust|rust[-_ ]scan"
    r"|detector_hit|scanner_hit|scan_hit)\b",
    re.IGNORECASE,
)

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _short_hash(text: str, length: int = 12) -> str:
    return hashlib.sha256(text.encode()).hexdigest()[:length]


def _read_json(path: Path) -> Any:
    """Read a JSON file, returning None on any error."""
    try:
        return json.loads(path.read_text(encoding="utf-8", errors="replace"))
    except (OSError, json.JSONDecodeError, ValueError):
        return None


def _has_detector_hit(artifact: dict[str, Any]) -> bool:
    """Return True if this artifact carries evidence that a detector fired.

    Mirrors _has_detector_hit from base-critical-hunt.py (read-only reuse).

    Checks explicit hit fields first. Falls back to DETECTOR_HINT_RE only on
    structured metadata fields (title, verdict, artifact_type, verification_tier,
    provenance_ref), NOT on 'content'. This avoids false positives from content
    text like "No detector fired on this path" or "No scanner triggered".
    """
    for key in ("detector_hits", "scanner_hits", "scan_hits", "detectors"):
        value = artifact.get(key)
        if isinstance(value, list) and value:
            return True
        if isinstance(value, str) and value.strip():
            return True
    # Restrict regex to hit-carrying metadata fields only. Exclude 'content',
    # 'artifact_type', and 'artifact_id':
    #   - 'content' is free text that may say "no detector fired" (FP)
    #   - 'artifact_type' contains literal "detector" in 'candidate_detector_pattern'
    #     which represents the artifact kind, NOT a scanner fire (FP)
    hit_fields = ("title", "verdict", "provenance_ref", "verification_tier")
    hit_blob = json.dumps(
        {k: artifact.get(k, "") for k in hit_fields},
        ensure_ascii=False,
    )
    return bool(DETECTOR_HINT_RE.search(hit_blob))


def _is_agent_found(artifact: dict[str, Any]) -> bool:
    """Return True if this artifact was surfaced by an agent read (not a detector).

    Mirrors AGENT_HINT_RE from base-critical-hunt.py. We check both the
    artifact fields and the full blob so that provenance_ref paths with
    'agent_outputs' or 'claude' in them also register.
    """
    blob = json.dumps(artifact, ensure_ascii=False)
    return bool(AGENT_HINT_RE.search(blob))


def _durable_route(artifact: dict[str, Any]) -> str:
    """Derive the durable route for a recall-gap artifact.

    - 'detector_gap': the behavior has a detector pattern candidate signal;
      route is to build/refine a detector.
    - 'source_review': no detector pattern signal; route is continued manual
      source reading with a specific question.

    Falls back to any explicit durable_route field in the artifact.
    """
    # Explicit field from miner output wins
    explicit = artifact.get("durable_route", "")
    if explicit and explicit not in ("detector_gap_or_source_review",):
        return str(explicit)

    art_type = artifact.get("artifact_type", "")
    # candidate_detector_pattern artifacts -> detector_gap
    if art_type == "candidate_detector_pattern":
        return "detector_gap"
    # candidate_hacker_question -> source_review (needs local follow-up)
    if art_type == "candidate_hacker_question":
        return "source_review"
    # harness_template_request -> detector_gap (missing harness is a gap)
    if art_type == "harness_template_request":
        return "detector_gap"
    # known_limitation / roadmap_gap -> source_review
    if art_type in ("known_limitation", "roadmap_gap"):
        return "source_review"
    # falsification_template -> source_review (negative control, not a detector yet)
    if art_type == "falsification_template":
        return "source_review"

    # Fallback: does the artifact content mention detector-pattern language?
    content = artifact.get("content", "") or ""
    if DETECTOR_HINT_RE.search(content):
        return "detector_gap"
    return "source_review"


def _behavior_id(artifact: dict[str, Any], idx: int) -> str:
    """Stable behavior ID from artifact_id or content hash."""
    if artifact.get("artifact_id"):
        return str(artifact["artifact_id"])
    content = artifact.get("content", "") + artifact.get("provenance_ref", "")
    return f"arb-{_short_hash(content)}"


def _impact_family(artifact: dict[str, Any]) -> str:
    """Extract impact family from the artifact, falling back to artifact_type."""
    for key in ("impact_family", "impact_mapping", "listed_impact_selected"):
        val = artifact.get(key, "")
        if val and str(val).strip():
            return str(val).strip()
    # Use artifact_type as a proxy when impact family is not explicit
    return artifact.get("artifact_type", "unknown")


# ---------------------------------------------------------------------------
# Agent artifact loader
# ---------------------------------------------------------------------------


def _load_agent_artifacts(workspace: Path) -> list[dict[str, Any]]:
    """Load agent-artifact-mining report(s) from the workspace.

    Priority order:
    1. reports/agent_artifact_mining.json (pre-run output)
    2. .auditooor/agent_artifact_mining.json
    3. Run agent-artifact-miner.py in-process if neither exists.

    Returns a list of artifact dicts (may be empty on error or empty workspace).
    """
    candidates = [
        workspace / "reports" / "agent_artifact_mining.json",
        workspace / ".auditooor" / "agent_artifact_mining.json",
    ]
    for cand in candidates:
        data = _read_json(cand)
        if isinstance(data, dict) and isinstance(data.get("artifacts"), list):
            return data["artifacts"]

    # Fall back: run agent-artifact-miner.py in-process
    miner_path = Path(__file__).resolve().parent / "agent-artifact-miner.py"
    if not miner_path.is_file():
        return []

    try:
        spec = importlib.util.spec_from_file_location("agent_artifact_miner", miner_path)
        if spec is None or spec.loader is None:
            return []
        module = importlib.util.module_from_spec(spec)
        # Guard against re-registration if already loaded
        import sys as _sys
        _sys.modules.setdefault("agent_artifact_miner", module)
        spec.loader.exec_module(module)
        report = module.mine_workspace(workspace)
        return report.get("artifacts", [])
    except Exception:  # noqa: BLE001
        return []


# ---------------------------------------------------------------------------
# Detector output loader
# ---------------------------------------------------------------------------

_SCAN_OUTPUT_CANDIDATES = (
    "scanners/rust/SCAN_RUST_SUMMARY.json",
    "scanners/rust/SCAN_RUST_SUMMARY.md",
    "audit/rust-scan/summary.md",
    "audit/scan/summary.md",
    "scan_results.json",
    ".auditooor/coverage_inventory.json",
    "critical_hunt/hunt_run.json",
    "engage_report.json",
)


def _load_detector_outputs(workspace: Path) -> list[str]:
    """Collect available detector/scanner output file paths from the workspace.

    Returns a list of workspace-relative path strings for present artifact
    files. Used to enrich the recall classification context.
    """
    present = []
    for candidate in _SCAN_OUTPUT_CANDIDATES:
        path = workspace / candidate
        if path.is_file():
            present.append(candidate)
    # Also glob for any engage_report*.json in the workspace root
    for p in sorted(workspace.glob("engage_report*.json")):
        rel = str(p.relative_to(workspace))
        if rel not in present:
            present.append(rel)
    return present


# ---------------------------------------------------------------------------
# Core replay logic
# ---------------------------------------------------------------------------


def replay(workspace: Path) -> dict[str, Any]:
    """Replay agent-found behaviors and compute detectorized-vs-not split.

    This is an attention/ranking metric. Never use recall improvement as a
    proof signal. See module docstring for the full disclaimer.

    Returns a dict conforming to auditooor.agent_recall_replay.v1.
    """
    workspace = workspace.resolve()

    all_artifacts = _load_agent_artifacts(workspace)
    detector_artifacts_present = _load_detector_outputs(workspace)

    # Filter to agent-found behaviors only
    agent_found: list[dict[str, Any]] = [
        a for a in all_artifacts if _is_agent_found(a)
    ]

    # Classify each as detectorized or not
    detectorized: list[dict[str, Any]] = []
    recall_gaps: list[dict[str, Any]] = []

    for idx, artifact in enumerate(agent_found):
        if _has_detector_hit(artifact):
            detectorized.append(artifact)
        else:
            recall_gaps.append(artifact)

    total = len(agent_found)
    det_count = len(detectorized)
    gap_count = len(recall_gaps)
    recall_rate = round(det_count / total, 4) if total > 0 else 0.0

    # Build bounded gap rows with durable_route
    gap_rows: list[dict[str, Any]] = []
    for idx, artifact in enumerate(recall_gaps[:MAX_GAP_ROWS]):
        gap_rows.append(
            {
                "behavior_id": _behavior_id(artifact, idx),
                "artifact_type": artifact.get("artifact_type", "unknown"),
                "impact_family": _impact_family(artifact),
                "provenance_ref": artifact.get("provenance_ref", ""),
                "verification_tier": artifact.get("verification_tier", ""),
                "durable_route": _durable_route(artifact),
                "detector_status": "not_found",
                "content_summary": str(artifact.get("content", ""))[:200],
            }
        )

    # Build detectorized summary (non-bounded but lighter weight)
    detectorized_rows: list[dict[str, Any]] = []
    for artifact in detectorized:
        detectorized_rows.append(
            {
                "behavior_id": _behavior_id(artifact, 0),
                "artifact_type": artifact.get("artifact_type", "unknown"),
                "impact_family": _impact_family(artifact),
                "provenance_ref": artifact.get("provenance_ref", ""),
                "detector_status": "found",
            }
        )

    return {
        "schema_version": SCHEMA_VERSION,
        "workspace": str(workspace),
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "attention_metric_only": (
            "Recall is an attention/ranking metric. "
            "Never use recall improvement as a proof signal."
        ),
        "total_agent_found_behaviors": total,
        "detectorized_count": det_count,
        "non_detectorized_count": gap_count,
        "recall_rate": recall_rate,
        "recall_rate_pct": round(recall_rate * 100, 2),
        "detector_artifacts_present": detector_artifacts_present,
        "recall_gap_behaviors": gap_rows,
        "detectorized_behaviors": detectorized_rows,
        "gap_rows_truncated": len(recall_gaps) > MAX_GAP_ROWS,
        "gap_rows_total": gap_count,
    }


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------


def _build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        description=(
            "Replay agent-found behaviors and measure the detectorized-vs-not split. "
            "Recall is an attention/ranking metric only - never a proof signal."
        ),
    )
    p.add_argument(
        "--workspace",
        required=True,
        help="Path to the audit workspace root.",
    )
    p.add_argument(
        "--out",
        metavar="FILE",
        help="Write JSON report to this file (default: stdout).",
    )
    p.add_argument(
        "--json",
        dest="emit_json",
        action="store_true",
        help="Emit JSON to stdout (same as omitting --out).",
    )
    return p


def main(argv: list[str] | None = None) -> int:
    parser = _build_parser()
    args = parser.parse_args(argv)

    ws = Path(args.workspace).expanduser()
    if not ws.is_dir():
        print(f"ERROR: workspace not found: {ws}", file=sys.stderr)
        return 2

    report = replay(ws)
    out_text = json.dumps(report, indent=2, ensure_ascii=False)

    if args.out:
        out_path = Path(args.out)
        out_path.parent.mkdir(parents=True, exist_ok=True)
        out_path.write_text(out_text + "\n", encoding="utf-8")
        print(
            f"agent-recall-replay: total={report['total_agent_found_behaviors']} "
            f"detectorized={report['detectorized_count']} "
            f"gaps={report['non_detectorized_count']} "
            f"recall_rate={report['recall_rate_pct']}% "
            f"-> {out_path}",
            file=sys.stderr,
        )
    else:
        print(out_text)

    return 0


if __name__ == "__main__":
    sys.exit(main())
