#!/usr/bin/env python3
# r36-rebuttal: lane GAP-FIX-1-gap29 registered in .auditooor/agent_pathspec.json via tools/agent-pathspec-register.py
"""Gap #29 hunt-phase ordering preflight.

Drill / hunt / composition lanes MUST NOT spawn before ``make audit`` has
completed for the workspace. If they do, the drill operates on a stale
``docs/LIVE_TARGET_REPORT.md`` (or other audit-derived artifacts) and the
hypothesis surface is unreliable.

This gate verifies:
  1. The workspace ``<ws>/.auditooor/last_audit_complete_marker`` exists.
  2. The marker's modification time is >= the modification time of
     ``<ws>/docs/LIVE_TARGET_REPORT.md`` (audit must have run AFTER the live
     target report was last updated by the prior hunt cycle, OR the marker
     was created in the same audit pass).

When the lane being checked is NOT a drill / hunt / composition lane, the
check passes with ``pass-not-drill-lane``.

Override marker:
  ``<!-- gap29-rebuttal: <reason up to 200 chars> -->``
  or the visible bounded line ``gap29-rebuttal: <reason>``.

Verdicts:
  - pass-audit-complete-before-drill: marker present + fresh
  - pass-not-drill-lane: lane-type / lane-id is not drill/hunt/composition
  - ok-rebuttal: bounded gap29-rebuttal accepted
  - fail-drill-before-audit: marker missing entirely
  - fail-stale-audit-state: marker is older than LIVE_TARGET_REPORT.md
  - error: input / IO error

Exit codes:
  0 - pass / ok-rebuttal / pass-not-drill-lane
  1 - fail-* verdict
  2 - error

Schema: ``auditooor.gap29_hunt_phase_ordering.v1``.

Empirical anchor (2026-05-26): drills firing before ``make audit`` completes
read stale ``docs/LIVE_TARGET_REPORT.md`` and pursue stale hypotheses.
"""

from __future__ import annotations

# r36-rebuttal: lane fix-2-deeper-gaps-2026-05-28 — add os import for CAP-GAP-NI-9 tolerance env var
import argparse
import json
import os
import re
import sys
from pathlib import Path
from typing import Any


SCHEMA_VERSION = "auditooor.gap29_hunt_phase_ordering.v1"
GATE = "GAP29-HUNT-PHASE-ORDERING"
TOOL_REL_PATH = "tools/hunt-phase-ordering-check.py"

# Lane types subject to the gate. The gate fires when the lane is hunt /
# drill / composition / comp.
GATED_LANE_TYPES = {
    "hunt",
    "drill",
    "comp",
    "composition",
    "opposed-trace-harness",
}

# Lane-id substring patterns that imply the lane is a drill-class lane even
# when the lane-type is something else (tool-build wrappers around a drill,
# etc.).
GATED_LANE_ID_PATTERNS = [
    r"\bdrill\b",
    r"\bhunt\b",
    r"\bcomp\b",
    r"\bopposed[-_]trace\b",
    r"DRILL",
    r"HUNT",
    r"COMP",
]

REBUTTAL_HTML_RE = re.compile(
    r"<!--\s*gap29[-_ ]rebuttal\s*:\s*(.*?)\s*-->",
    re.IGNORECASE | re.DOTALL,
)
REBUTTAL_LINE_RE = re.compile(
    r"(?im)^\s*(?:[-*]\s*)?gap29[-_ ]rebuttal\s*:\s*(.+?)\s*$",
)

MAX_REBUTTAL_LEN = 200

DEFAULT_MARKER_REL = ".auditooor/last_audit_complete_marker"
DEFAULT_LIVE_TARGET_REL = "docs/LIVE_TARGET_REPORT.md"


def _emit(payload: dict[str, Any], as_json: bool) -> None:
    payload.setdefault("schema", SCHEMA_VERSION)
    payload.setdefault("gate", GATE)
    payload.setdefault("tool", TOOL_REL_PATH)
    if as_json:
        print(json.dumps(payload, indent=2, sort_keys=True))
    else:
        v = payload.get("verdict", "?")
        r = payload.get("reason", "")
        print(f"[{GATE}] verdict={v} reason={r}")


def _lane_is_gated(lane_type: str, lane_id: str) -> bool:
    if (lane_type or "").lower() in GATED_LANE_TYPES:
        return True
    if not lane_id:
        return False
    for pat in GATED_LANE_ID_PATTERNS:
        if re.search(pat, lane_id):
            return True
    return False


def _extract_rebuttal(text: str) -> str | None:
    """Return the rebuttal reason if a non-empty bounded marker is present."""
    if not text:
        return None
    m = REBUTTAL_HTML_RE.search(text)
    if not m:
        m = REBUTTAL_LINE_RE.search(text)
    if not m:
        return None
    reason = (m.group(1) or "").strip()
    if not reason:
        return None
    if len(reason) > MAX_REBUTTAL_LEN:
        return None
    return reason


def _file_mtime(path: Path) -> float | None:
    try:
        return path.stat().st_mtime
    except FileNotFoundError:
        return None
    except OSError:
        return None


def check(
    workspace: Path,
    lane_id: str,
    lane_type: str,
    rebuttal_text: str = "",
    marker_rel: str = DEFAULT_MARKER_REL,
    live_target_rel: str = DEFAULT_LIVE_TARGET_REL,
) -> dict[str, Any]:
    if not workspace.exists():
        return {
            "verdict": "error",
            "reason": f"workspace path does not exist: {workspace}",
            "exit": 2,
        }

    if not _lane_is_gated(lane_type, lane_id):
        return {
            "verdict": "pass-not-drill-lane",
            "reason": (
                f"lane_type={lane_type!r} lane_id={lane_id!r} is not a "
                "drill / hunt / composition lane; gate does not fire"
            ),
            "exit": 0,
            "lane_id": lane_id,
            "lane_type": lane_type,
        }

    # Rebuttal short-circuit only applies for gated lanes.
    rebuttal = _extract_rebuttal(rebuttal_text)
    if rebuttal:
        return {
            "verdict": "ok-rebuttal",
            "reason": f"gap29-rebuttal accepted: {rebuttal}",
            "exit": 0,
            "lane_id": lane_id,
            "lane_type": lane_type,
        }

    marker_path = workspace / marker_rel
    live_target_path = workspace / live_target_rel

    marker_mtime = _file_mtime(marker_path)
    live_target_mtime = _file_mtime(live_target_path)

    if marker_mtime is None:
        return {
            "verdict": "fail-drill-before-audit",
            "reason": (
                f"audit-complete marker missing at {marker_path}; drill "
                "lanes must wait for `make audit` to complete and write "
                "the marker"
            ),
            "exit": 1,
            "lane_id": lane_id,
            "lane_type": lane_type,
            "marker_path": str(marker_path),
            "live_target_path": str(live_target_path),
            "marker_present": False,
            "remediation": (
                "Either: (a) run `make audit WS=<ws>` and let it write the "
                f"marker {marker_rel}, or (b) add "
                "`<!-- gap29-rebuttal: <reason up to 200 chars> -->` to the "
                "lane brief / prompt text"
            ),
        }

    # r36-rebuttal: lane fix-2-deeper-gaps-2026-05-28
    # CAP-GAP-NI-9: `make hunt` legitimately updates LIVE_TARGET_REPORT.md
    # via its `live-target-intel` stage AFTER the audit-marker is written
    # (the marker is written at end of `make audit`, then `make hunt` runs
    # later). Without tolerance, every `make hunt` cycle requires a fresh
    # `make audit` re-run, which is wasteful when the audit artifacts are
    # genuinely unchanged. SAME-LANE / SAME-CYCLE tolerance: allow
    # LIVE_TARGET_REPORT.md to be UP TO N seconds newer than the marker
    # (default 3600s = 1 hour, configurable via AUDITOOOR_GAP29_TOLERANCE_S).
    # Beyond N seconds, fail-stale-audit-state still fires.
    _tolerance_s = int(os.environ.get("AUDITOOOR_GAP29_TOLERANCE_S", "3600"))
    if live_target_mtime is not None and live_target_mtime > marker_mtime:
        delta_s = live_target_mtime - marker_mtime
        if delta_s <= _tolerance_s:
            return {
                "verdict": "pass-audit-complete-with-hunt-refresh",
                "reason": (
                    f"audit marker present (mtime={marker_mtime}); "
                    f"LIVE_TARGET_REPORT.md is {int(delta_s)}s newer "
                    f"(within {_tolerance_s}s tolerance — typical "
                    "make hunt live-target-intel refresh of same audit cycle)"
                ),
                "exit": 0,
                "lane_id": lane_id,
                "lane_type": lane_type,
                "marker_path": str(marker_path),
                "marker_mtime": marker_mtime,
                "live_target_path": str(live_target_path),
                "live_target_mtime": live_target_mtime,
                "tolerance_s": _tolerance_s,
                "delta_s": int(delta_s),
            }
        return {
            "verdict": "fail-stale-audit-state",
            "reason": (
                f"audit marker mtime ({marker_mtime}) is older than "
                f"LIVE_TARGET_REPORT.md mtime ({live_target_mtime}); "
                f"delta={int(delta_s)}s exceeds tolerance {_tolerance_s}s; "
                "audit must be re-run before drilling"
            ),
            "exit": 1,
            "lane_id": lane_id,
            "lane_type": lane_type,
            "marker_path": str(marker_path),
            "marker_mtime": marker_mtime,
            "live_target_path": str(live_target_path),
            "live_target_mtime": live_target_mtime,
            "tolerance_s": _tolerance_s,
            "delta_s": int(delta_s),
            "remediation": (
                "Re-run `make audit WS=<ws>` to refresh the marker after "
                "any update to LIVE_TARGET_REPORT.md, OR raise "
                "AUDITOOOR_GAP29_TOLERANCE_S env (default 3600) if this "
                "delta represents a legitimate same-cycle refresh"
            ),
        }

    return {
        "verdict": "pass-audit-complete-before-drill",
        "reason": (
            f"audit marker present at {marker_path} "
            f"(mtime={marker_mtime}); ordering ok"
        ),
        "exit": 0,
        "lane_id": lane_id,
        "lane_type": lane_type,
        "marker_path": str(marker_path),
        "marker_mtime": marker_mtime,
        "live_target_mtime": live_target_mtime,
    }


def _read_optional_text(path: Path | None) -> str:
    if path is None:
        return ""
    try:
        return path.read_text(encoding="utf-8", errors="replace")
    except FileNotFoundError:
        return ""
    except OSError:
        return ""


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(
        description=(
            "Gap #29 hunt-phase ordering preflight. Refuses drill / hunt / "
            "composition lane dispatch when `make audit` has not completed "
            "for the workspace (no marker) or when the marker is stale "
            "relative to docs/LIVE_TARGET_REPORT.md."
        ),
    )
    p.add_argument("--workspace", required=True, help="Workspace path.")
    p.add_argument("--lane-id", required=True, help="Lane id (e.g. DRILL-9, HUNT-A).")
    p.add_argument(
        "--lane-type",
        default="",
        help="Lane type (drill / hunt / comp / dispute / tool-build / capability).",
    )
    p.add_argument(
        "--prompt-file",
        default=None,
        help="Optional path to lane brief / prompt file; scanned for gap29-rebuttal marker.",
    )
    p.add_argument(
        "--rebuttal-text",
        default="",
        help="Optional inline rebuttal text (alternative to --prompt-file).",
    )
    p.add_argument(
        "--marker-rel",
        default=DEFAULT_MARKER_REL,
        help=f"Workspace-relative path to audit-complete marker (default: {DEFAULT_MARKER_REL}).",
    )
    p.add_argument(
        "--live-target-rel",
        default=DEFAULT_LIVE_TARGET_REL,
        help=f"Workspace-relative path to live-target report (default: {DEFAULT_LIVE_TARGET_REL}).",
    )
    p.add_argument("--json", action="store_true", help="Emit JSON verdict payload.")
    args = p.parse_args(argv)

    ws = Path(args.workspace).expanduser()

    prompt_text = ""
    if args.prompt_file:
        prompt_text = _read_optional_text(Path(args.prompt_file).expanduser())
    if args.rebuttal_text:
        prompt_text = (prompt_text + "\n" + args.rebuttal_text).strip()

    result = check(
        workspace=ws,
        lane_id=args.lane_id,
        lane_type=args.lane_type,
        rebuttal_text=prompt_text,
        marker_rel=args.marker_rel,
        live_target_rel=args.live_target_rel,
    )

    exit_code = int(result.pop("exit", 0))
    _emit(result, args.json)
    return exit_code


if __name__ == "__main__":
    sys.exit(main())
