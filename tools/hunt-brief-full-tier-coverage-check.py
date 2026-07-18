#!/usr/bin/env python3
# r36-rebuttal: lane IMP-ZK-ENFORCE registered in .auditooor/agent_pathspec.json agents[]
"""G13.2 hunt-brief full-tier-coverage preflight.

# G13: this tool emits no corpus record.

Hunt-class lanes (hunt / drill / comp / fuzz / opposed-trace-harness /
escalation) MUST be briefed with the FULL SEVERITY.md tier surface and an
explicit "hunt every tier" directive, otherwise the worker tends to
freestyle a Critical-only hunt and never enumerates the Low/Medium-rich
library surface (Aztec cold-run anchor: 18/121 concrete contracts drilled,
all libraries skipped, zero Low/Medium candidates emitted).

This gate validates the POST-enrichment brief (the file the dispatcher
actually produced via the G13.1 ``_format_full_rubric_tier_section``
injection) by:

  1. Parsing the workspace SEVERITY.md tier set via the shared
     ``lib.severity_rubric`` parser (single source of truth with R52).
  2. Confirming every parsed tier name appears in the brief text.
  3. Confirming a full-tier-coverage directive phrase appears in the brief.

Fires ONLY for hunt-class lane types; other lanes pass with
``pass-not-hunt-lane``. When the workspace has no SEVERITY.md the gate
cannot enforce tier coverage and passes with ``pass-no-severity-md`` (warn).

Verdicts:
  pass-not-hunt-lane            - lane is not hunt-class
  pass-no-severity-md           - workspace has no SEVERITY.md (warn)
  pass-full-tier-coverage-present - all tiers named + directive present
  ok-rebuttal                   - bounded g13-rebuttal accepted
  fail-missing-tier-in-brief    - a fileable tier from SEVERITY.md is absent
  fail-no-full-tier-directive   - tiers present but no "hunt every tier"
                                  directive (Critical-bias risk)
  error                         - input / IO error

Exit codes:
  0 - pass / ok-rebuttal / pass-not-hunt-lane / pass-no-severity-md
  1 - fail-* verdict
  2 - error

Override marker: visible bounded line ``g13-rebuttal: <reason>`` (<=200
chars) OR HTML-comment form ``<!-- g13-rebuttal: <reason> -->``.

Schema: ``auditooor.g13_hunt_brief_full_tier_coverage.v1``.
"""

from __future__ import annotations

import argparse
import json
import re
import sys
from pathlib import Path
from typing import Any

# r36-rebuttal: lane IMP-ZK-ENFORCE registered in .auditooor/agent_pathspec.json agents[]
try:
    sys.path.insert(0, str(Path(__file__).resolve().parent))
    from lib import severity_rubric as _severity_rubric  # type: ignore
except Exception:  # pragma: no cover - lib optional
    _severity_rubric = None


SCHEMA_VERSION = "auditooor.g13_hunt_brief_full_tier_coverage.v1"
GATE = "G13-HUNT-BRIEF-FULL-TIER-COVERAGE"
TOOL_REL_PATH = "tools/hunt-brief-full-tier-coverage-check.py"

# Hunt-class lane types subject to the gate (matches G13.1 injection set).
GATED_LANE_TYPES = {
    "hunt",
    "drill",
    "comp",
    "fuzz",
    "opposed-trace-harness",
    "escalation",
}

GATED_LANE_ID_PATTERNS = [
    r"\bdrill\b",
    r"\bhunt\b",
    r"\bcomp\b",
    r"\bfuzz\b",
    r"\bescalation\b",
    r"\bopposed[-_]trace\b",
    r"DRILL",
    r"HUNT",
    r"FUZZ",
]

# Full-tier-coverage directive phrases (any one present satisfies the gate).
DIRECTIVE_PHRASES = [
    r"hunt\s+(?:and\s+file\s+)?every\s+tier",
    r"every\s+tier\s+Low",
    r"all\s+tiers\s+are\s+fileable",
    r"Low\s+and\s+Medium\b.{0,40}\bfileable",
    r"file\s+EVERY\s+tier",
]

REBUTTAL_HTML_RE = re.compile(
    r"<!--\s*g13[-_ ]rebuttal\s*:\s*(.*?)\s*-->",
    re.IGNORECASE | re.DOTALL,
)
REBUTTAL_LINE_RE = re.compile(
    r"(?im)^\s*(?:[-*]\s*)?g13[-_ ]rebuttal\s*:\s*(.+?)\s*$",
)
MAX_REBUTTAL_LEN = 200


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
    if not text:
        return None
    m = REBUTTAL_HTML_RE.search(text)
    if not m:
        m = REBUTTAL_LINE_RE.search(text)
    if not m:
        return None
    reason = (m.group(1) or "").strip()
    if not reason or len(reason) > MAX_REBUTTAL_LEN:
        return None
    return reason


def _directive_present(text: str) -> bool:
    for pat in DIRECTIVE_PHRASES:
        if re.search(pat, text, re.IGNORECASE | re.DOTALL):
            return True
    return False


def _tier_present(tier: str, text: str) -> bool:
    # Tier name as a whole word, case-insensitive.
    return re.search(rf"\b{re.escape(tier)}\b", text, re.IGNORECASE) is not None


def check(
    workspace: Path,
    lane_id: str,
    lane_type: str,
    brief_text: str,
) -> dict[str, Any]:
    if not _lane_is_gated(lane_type, lane_id):
        return {
            "verdict": "pass-not-hunt-lane",
            "reason": (
                f"lane_type={lane_type!r} lane_id={lane_id!r} is not a "
                "hunt-class lane; gate does not fire"
            ),
            "exit": 0,
            "lane_id": lane_id,
            "lane_type": lane_type,
        }

    rebuttal = _extract_rebuttal(brief_text)
    if rebuttal:
        return {
            "verdict": "ok-rebuttal",
            "reason": f"g13-rebuttal accepted: {rebuttal}",
            "exit": 0,
            "lane_id": lane_id,
            "lane_type": lane_type,
        }

    if _severity_rubric is None:
        return {
            "verdict": "error",
            "reason": "lib.severity_rubric unavailable; cannot parse tiers",
            "exit": 2,
        }

    sev_md = _severity_rubric.find_severity_md(workspace)
    if sev_md is None:
        return {
            "verdict": "pass-no-severity-md",
            "reason": (
                f"no SEVERITY.md under {workspace}; cannot enforce full-tier "
                "coverage (run `make audit-prep WS=<ws>` to scaffold the rubric)"
            ),
            "exit": 0,
            "lane_id": lane_id,
            "lane_type": lane_type,
        }

    try:
        rows = _severity_rubric.parse_tier_rows(
            sev_md.read_text(encoding="utf-8", errors="replace")
        )
    except OSError as exc:
        return {
            "verdict": "error",
            "reason": f"cannot read SEVERITY.md at {sev_md}: {exc}",
            "exit": 2,
        }

    tiers = sorted(_severity_rubric.tier_set(rows))
    if not tiers:
        return {
            "verdict": "pass-no-severity-md",
            "reason": (
                f"SEVERITY.md at {sev_md} parsed zero tier rows; cannot "
                "enforce full-tier coverage"
            ),
            "exit": 0,
            "lane_id": lane_id,
            "lane_type": lane_type,
            "severity_md": str(sev_md),
        }

    missing = [t for t in tiers if not _tier_present(t, brief_text)]
    if missing:
        return {
            "verdict": "fail-missing-tier-in-brief",
            "reason": (
                f"brief omits fileable tier(s) {missing} present in "
                f"{sev_md}; the worker may freestyle a partial-tier hunt"
            ),
            "exit": 1,
            "lane_id": lane_id,
            "lane_type": lane_type,
            "severity_md": str(sev_md),
            "rubric_tiers": tiers,
            "missing_tiers": missing,
            "remediation": (
                "Ensure the dispatcher injected Section 15i-FULL "
                "(_format_full_rubric_tier_section); re-run "
                "tools/dispatch-agent-with-prebriefing.py for this lane, or "
                "add `<!-- g13-rebuttal: <reason up to 200 chars> -->`."
            ),
        }

    if not _directive_present(brief_text):
        return {
            "verdict": "fail-no-full-tier-directive",
            "reason": (
                "all tiers are named but no 'hunt every tier' directive is "
                "present; the worker may bias toward Critical-only findings"
            ),
            "exit": 1,
            "lane_id": lane_id,
            "lane_type": lane_type,
            "severity_md": str(sev_md),
            "rubric_tiers": tiers,
            "remediation": (
                "Inject the G13.1 MANDATORY directive ('hunt and file EVERY "
                "tier Low -> Critical'), or add "
                "`<!-- g13-rebuttal: <reason> -->`."
            ),
        }

    return {
        "verdict": "pass-full-tier-coverage-present",
        "reason": (
            f"all {len(tiers)} fileable tiers {tiers} named in brief + "
            "full-tier directive present"
        ),
        "exit": 0,
        "lane_id": lane_id,
        "lane_type": lane_type,
        "severity_md": str(sev_md),
        "rubric_tiers": tiers,
    }


def _read_optional_text(path: Path | None) -> str:
    if path is None:
        return ""
    try:
        return path.read_text(encoding="utf-8", errors="replace")
    except (FileNotFoundError, OSError):
        return ""


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(
        description=(
            "G13.2 hunt-brief full-tier-coverage preflight. Refuses hunt-class "
            "lane dispatch when the enriched brief omits a fileable SEVERITY.md "
            "tier or lacks a 'hunt every tier' directive."
        ),
    )
    p.add_argument("--workspace", required=True, help="Workspace path.")
    p.add_argument("--lane-id", required=True, help="Lane id (e.g. HUNT-A, DRILL-9).")
    p.add_argument(
        "--lane-type",
        default="",
        help="Lane type (hunt / drill / comp / fuzz / opposed-trace-harness / escalation).",
    )
    p.add_argument(
        "--prompt-file",
        default=None,
        help="Path to the POST-enrichment brief / prompt file to validate.",
    )
    p.add_argument(
        "--prompt-text",
        default="",
        help="Optional inline brief text (alternative to --prompt-file).",
    )
    p.add_argument("--json", action="store_true", help="Emit JSON verdict payload.")
    args = p.parse_args(argv)

    ws = Path(args.workspace).expanduser()

    brief_text = ""
    if args.prompt_file:
        brief_text = _read_optional_text(Path(args.prompt_file).expanduser())
    if args.prompt_text:
        brief_text = (brief_text + "\n" + args.prompt_text).strip()

    result = check(
        workspace=ws,
        lane_id=args.lane_id,
        lane_type=args.lane_type,
        brief_text=brief_text,
    )

    exit_code = int(result.pop("exit", 0))
    _emit(result, args.json)
    return exit_code


if __name__ == "__main__":
    sys.exit(main())
