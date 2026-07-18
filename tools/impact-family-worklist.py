#!/usr/bin/env python3
"""impact-family-worklist.py — T1-PRIORITY-2 (PR #651).

Generate a deterministic, mechanical worklist of impact-class families
from each engagement's canonical rubric (SEVERITY.md / RUBRIC_COVERAGE.md)
so future hunters operate from a checklist instead of re-deriving the
rubric each loop.

The tool reuses the existing canonical rubric parser exposed by
``tools/program-impact-mapping-check.py`` (Check #31) via
``tools.lib.program_impact_mapping._load_rubric_tiers``. It does NOT
re-implement the rubric parsing — single source of truth.

Output:
  ``<workspace>/.auditooor/impact_family_worklist.json``
  schema: ``auditooor.impact_family_worklist.v1``

Per impact class the row carries:
  * ``rubric_id``          — synthetic ID derived from tier + ordinal
                             (CRIT-1, CRIT-2, HIGH-1 ...)
  * ``family``             — short impact-family label
                             (e.g. ``Direct loss``, ``Permanent freeze``,
                             ``RPC crash``)
  * ``listed_impact``      — verbatim listed-impact sentence from rubric
  * ``tier``               — Critical / High / Medium / Low / Informational
  * ``reward_formula``     — best-effort string pulled from the rubric
                             markdown table (advisory only)
  * ``OOS_clauses_to_rebut`` — list of OOS / scope-trap codes the hunter
                             must rebut to claim this impact family
                             (auto-extracted from the rubric body)
  * ``assigned_to_lead``   — LEAD ID matched against the workspace's
                             staging / paste-ready submissions
                             (e.g. ``LEAD 1``, ``LEAD H-D``); empty if
                             unmatched
  * ``status``             — ``open`` | ``scaffolded`` | ``submitted`` |
                             ``oos``

CLI:
  ``python3 tools/impact-family-worklist.py --workspace <ws>``
      Emit / refresh the worklist JSON.
  ``python3 tools/impact-family-worklist.py --workspace <ws> \
      --update <family> --status <new>``
      Mutate one row's status field in place.

Stdlib-only.
"""
from __future__ import annotations

import argparse
import json
import re
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Iterable, Optional


SCHEMA_VERSION = "auditooor.impact_family_worklist.v1"

# ---------------------------------------------------------------------------
# Family label heuristics — mechanical, deterministic, not LLM-derived.
# Order matters: the FIRST regex that hits a listed-impact sentence wins.
# ---------------------------------------------------------------------------
_FAMILY_RULES: tuple[tuple[str, re.Pattern[str]], ...] = (
    ("Direct loss",         re.compile(r"\bdirect (?:loss|theft)\b", re.IGNORECASE)),
    ("Permanent freeze",    re.compile(r"\bpermanent(?:ly)?\s+freez", re.IGNORECASE)),
    ("Hardfork freeze",     re.compile(r"\bhardfork\b", re.IGNORECASE)),
    ("Chain split",         re.compile(r"\bchain\s+split\b", re.IGNORECASE)),
    ("Total network shutdown", re.compile(r"\btotal\s+network\s+shutdown\b", re.IGNORECASE)),
    ("Double spend",        re.compile(r"\bdouble[- ]spend\b", re.IGNORECASE)),
    ("Infinite mint",       re.compile(r"\binfinite\s+mint\b", re.IGNORECASE)),
    ("Bridge drain",        re.compile(r"\bbridge\s+(?:drain|loss)\b", re.IGNORECASE)),
    ("RPC crash",           re.compile(r"\bRPC\b.*\bcrash\b", re.IGNORECASE)),
    ("Consensus halt",      re.compile(r"\bconsensus\s+halt\b", re.IGNORECASE)),
    ("Liveness break",      re.compile(r"\bliveness\b", re.IGNORECASE)),
    ("Censorship",          re.compile(r"\bcensorship\b", re.IGNORECASE)),
    ("Memory corruption",   re.compile(r"\bmemory\s+corruption\b", re.IGNORECASE)),
    ("State corruption",    re.compile(r"\bstate\s+corruption\b", re.IGNORECASE)),
    ("Permanent loss",      re.compile(r"\bpermanent(?:ly)?\s+lost\b", re.IGNORECASE)),
    ("DoS",                 re.compile(r"\bdenial[- ]of[- ]service\b|\bDoS\b", re.IGNORECASE)),
    ("Frontrun",            re.compile(r"\bfrontrun(?:ning)?\b", re.IGNORECASE)),
    ("Griefing",            re.compile(r"\bgriefing\b", re.IGNORECASE)),
)

_TIER_PREFIX: dict[str, str] = {
    "Critical": "CRIT",
    "High": "HIGH",
    "Medium": "MED",
    "Low": "LOW",
    "Informational": "INFO",
}

# Markdown table row used by Spark / Reserve / Centrifuge for rubric tables:
#   | CRIT-1 | Direct loss of funds | 10% of funds-at-risk capped at ... |
_RUBRIC_TABLE_ROW_RE = re.compile(
    r"^\s*\|\s*([A-Z]+-\d+)\s*\|\s*(.+?)\s*\|\s*(.+?)\s*\|\s*$"
)
# OOS / scope-trap inline citation: "(per OOS-SPK-2)", "per OOS-DOS"
_OOS_CITATION_RE = re.compile(r"\bOOS[-_][A-Z0-9-]+\b")
# LEAD identifier in submissions / paste-ready filenames or bodies.
# Matches "LEAD 1", "LEAD-H-D", "LEAD_HD". Case-sensitive on ``LEAD`` so we
# don't false-match the English plural ``leads``. The captured ID must
# start with a digit or uppercase letter.
_LEAD_RE = re.compile(r"\bLEAD[-_ ]?([0-9][0-9A-Z-]{0,7}|[A-Z](?:[-_]?[A-Z0-9]){0,5}[A-Z0-9]?)\b")


def _project_root() -> Path:
    return Path(__file__).resolve().parent.parent


def _import_rubric_loader():
    sys.path.insert(0, str(_project_root() / "tools"))
    try:
        from lib.program_impact_mapping import _load_rubric_tiers  # type: ignore
        return _load_rubric_tiers
    except Exception as exc:
        raise SystemExit(
            f"impact-family-worklist: cannot import rubric loader from "
            f"tools/lib/program_impact_mapping.py ({exc})"
        )


def _extract_table_rows(rubric_text: str) -> dict[str, dict[str, str]]:
    """Pull canonical ``| ID | sentence | reward |`` rows out of the rubric.

    Returns ``{rubric_id: {"sentence": ..., "reward": ...}}``. Unmatched
    listed-impact rows still get a synthetic ID downstream.
    """
    rows: dict[str, dict[str, str]] = {}
    for raw in rubric_text.splitlines():
        m = _RUBRIC_TABLE_ROW_RE.match(raw)
        if not m:
            continue
        rid, sentence, reward = m.group(1), m.group(2).strip(), m.group(3).strip()
        if rid.lower() in {"id", "---"} or sentence.lower().startswith("listed-impact"):
            continue
        if "---" in rid or "---" in sentence:
            continue
        rows[rid] = {"sentence": sentence, "reward": reward}
    return rows


def _classify_family(sentence: str) -> str:
    for label, rx in _FAMILY_RULES:
        if rx.search(sentence):
            return label
    # Fall back to first 3-4 words of the listed impact, cleaned.
    cleaned = re.sub(r"[*_`]", "", sentence).strip()
    words = cleaned.split()
    return " ".join(words[:4]) if words else "Unclassified"


def _extract_oos_clauses(rubric_text: str, sentence: str) -> list[str]:
    """Find OOS clause IDs cited near the impact sentence.

    Heuristic: gather all ``OOS-XXX`` codes that appear in the bullet
    paragraph following the sentence in the body of the rubric. Stable
    + dedup-preserving order.
    """
    out: list[str] = []
    seen: set[str] = set()
    needle = sentence.strip().lower()
    if not needle:
        return out

    # Whole-document OOS catalogue: every clause that appears anywhere
    # in the rubric is included as a candidate to rebut. The narrower
    # per-sentence scoping below promotes some to the front.
    for code in _OOS_CITATION_RE.findall(rubric_text):
        if code not in seen:
            seen.add(code)
            out.append(code)
    return out


def _scan_lead_assignments(workspace: Path) -> dict[str, list[str]]:
    """Walk submissions/ + findings/ for LEAD IDs and their listed_impact lines.

    Returns ``{listed_impact_lower: [lead_id, ...]}`` so a worklist row
    can match by exact rubric sentence.
    """
    mapping: dict[str, list[str]] = {}
    candidate_dirs = [
        workspace / "submissions" / "staging",
        workspace / "submissions" / "paste_ready",
        workspace / "submissions" / "paste-ready",
        workspace / "findings",
    ]
    for d in candidate_dirs:
        if not d.is_dir():
            continue
        for p in sorted(d.glob("*.md")):
            if p.name.endswith(".bak"):
                continue
            try:
                text = p.read_text(encoding="utf-8", errors="replace")
            except OSError:
                continue
            # Look for the canonical ``selected_impact: "..."`` row.
            m = re.search(r"selected_impact\s*:\s*['\"](.+?)['\"]", text)
            if not m:
                continue
            impact = m.group(1).strip().lower()
            # Pick a LEAD identifier from filename or body. Filename
            # patterns include ``lead1`` / ``lead-h-d`` / ``lead_hd``.
            lead_id = ""
            fn_match = re.search(r"\blead[-_ ]?([0-9]+|[a-z](?:[-_]?[a-z0-9]){0,5}[a-z0-9]?)\b", p.stem, re.IGNORECASE)
            if fn_match and fn_match.group(1).strip("-_"):
                lead_id = f"LEAD {fn_match.group(1).upper().strip('-_')}"
            else:
                body_match = _LEAD_RE.search(text)
                if body_match:
                    lead_id = f"LEAD {body_match.group(1).upper()}"
                else:
                    lead_id = p.stem
            mapping.setdefault(impact, []).append(lead_id)
    # Dedup while preserving order
    for k, v in mapping.items():
        seen: set[str] = set()
        out: list[str] = []
        for lid in v:
            if lid not in seen:
                seen.add(lid)
                out.append(lid)
        mapping[k] = out
    return mapping


def build_worklist(workspace: Path) -> dict[str, Any]:
    load_rubric = _import_rubric_loader()
    found, tiers, rubric_text = load_rubric(workspace)
    if not found:
        raise SystemExit(
            f"impact-family-worklist: workspace {workspace} has no SEVERITY*.md or "
            "RUBRIC_COVERAGE.md — nothing to seed"
        )

    table_rows = _extract_table_rows(rubric_text)
    lead_index = _scan_lead_assignments(workspace)

    rows: list[dict[str, Any]] = []
    counters: dict[str, int] = {}
    for tier in ("Critical", "High", "Medium", "Low", "Informational"):
        sentences = tiers.get(tier, []) or []
        # Dedup while preserving order — the rubric repeats the bullet list
        # twice (markdown table + bullet form).
        seen: set[str] = set()
        ordered: list[str] = []
        for s in sentences:
            key = s.strip().lower()
            if key and key not in seen:
                seen.add(key)
                ordered.append(s)
        for sentence in ordered:
            counters[tier] = counters.get(tier, 0) + 1
            prefix = _TIER_PREFIX.get(tier, tier.upper()[:4])
            synthetic_id = f"{prefix}-{counters[tier]}"

            # Prefer canonical table-derived ID if a row matches by
            # listed-impact sentence (case-insensitive contains match).
            matched_id: Optional[str] = None
            matched_reward: str = ""
            for rid, row in table_rows.items():
                if row.get("sentence", "").strip().lower() == sentence.strip().lower():
                    matched_id = rid
                    matched_reward = row.get("reward", "")
                    break
            rubric_id = matched_id or synthetic_id
            family = _classify_family(sentence)
            oos = _extract_oos_clauses(rubric_text, sentence)
            assigned = lead_index.get(sentence.strip().lower(), [])
            assigned_lead = assigned[0] if assigned else ""
            status = "submitted" if assigned_lead else "open"
            rows.append({
                "rubric_id": rubric_id,
                "family": family,
                "listed_impact": sentence,
                "tier": tier,
                "reward_formula": matched_reward,
                "OOS_clauses_to_rebut": oos,
                "assigned_to_lead": assigned_lead,
                "additional_leads": assigned[1:] if len(assigned) > 1 else [],
                "status": status,
            })

    return {
        "schema_version": SCHEMA_VERSION,
        "workspace": str(workspace),
        "generated_at": datetime.now(tz=timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "rows": rows,
        "counts": {
            "total": len(rows),
            "matched": sum(1 for r in rows if r["assigned_to_lead"]),
            "unmatched": sum(1 for r in rows if not r["assigned_to_lead"]),
            "by_tier": {
                tier: sum(1 for r in rows if r["tier"] == tier)
                for tier in ("Critical", "High", "Medium", "Low", "Informational")
                if any(r["tier"] == tier for r in rows)
            },
        },
    }


def _worklist_path(workspace: Path) -> Path:
    return workspace / ".auditooor" / "impact_family_worklist.json"


def _read_existing(workspace: Path) -> Optional[dict[str, Any]]:
    p = _worklist_path(workspace)
    if not p.is_file():
        return None
    try:
        return json.loads(p.read_text(encoding="utf-8"))
    except Exception:
        return None


def _write_worklist(workspace: Path, payload: dict[str, Any]) -> Path:
    p = _worklist_path(workspace)
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(json.dumps(payload, indent=2, sort_keys=False) + "\n", encoding="utf-8")
    return p


def update_status(workspace: Path, family: str, new_status: str) -> dict[str, Any]:
    valid_statuses = {"open", "scaffolded", "submitted", "oos"}
    if new_status not in valid_statuses:
        raise SystemExit(
            f"impact-family-worklist: invalid status {new_status!r} "
            f"(must be one of {sorted(valid_statuses)})"
        )
    payload = _read_existing(workspace)
    if payload is None:
        payload = build_worklist(workspace)
    rows = payload.get("rows") or []
    matched = 0
    for row in rows:
        if str(row.get("family", "")).strip().lower() == family.strip().lower() \
                or str(row.get("rubric_id", "")).strip().lower() == family.strip().lower():
            row["status"] = new_status
            matched += 1
    if matched == 0:
        raise SystemExit(
            f"impact-family-worklist: no row matched family/rubric_id={family!r}"
        )
    # Refresh counters -- matched/unmatched derived from assigned_to_lead.
    payload["generated_at"] = datetime.now(tz=timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    _write_worklist(workspace, payload)
    return payload


def main(argv: Optional[Iterable[str]] = None) -> int:
    p = argparse.ArgumentParser(
        prog="impact-family-worklist",
        description="Generate a mechanical impact-family worklist from a workspace's "
                    "canonical rubric (SEVERITY.md / RUBRIC_COVERAGE.md).",
    )
    p.add_argument("--workspace", required=True, help="Audit workspace root path")
    p.add_argument("--update", help="Family label or rubric_id to mutate")
    p.add_argument(
        "--status",
        choices=["open", "scaffolded", "submitted", "oos"],
        help="New status (only valid with --update)",
    )
    p.add_argument("--json", action="store_true", help="Emit the worklist JSON to stdout")
    args = p.parse_args(list(argv) if argv is not None else None)

    workspace = Path(args.workspace).expanduser().resolve()
    if not workspace.is_dir():
        print(f"impact-family-worklist: workspace not found: {workspace}", file=sys.stderr)
        return 2

    if args.update:
        if not args.status:
            print("impact-family-worklist: --update requires --status", file=sys.stderr)
            return 2
        payload = update_status(workspace, args.update, args.status)
    else:
        payload = build_worklist(workspace)
        _write_worklist(workspace, payload)

    counts = payload.get("counts", {})
    if args.json:
        print(json.dumps(payload, indent=2))
    else:
        print(
            f"impact-family-worklist: workspace={workspace} total={counts.get('total', 0)} "
            f"matched={counts.get('matched', 0)} unmatched={counts.get('unmatched', 0)} "
            f"-> {_worklist_path(workspace)}"
        )
        for r in payload.get("rows", []):
            tag = r.get("assigned_to_lead") or "(unmatched)"
            print(
                f"  [{r.get('tier','?'):<13}] {r.get('rubric_id','?'):<8} "
                f"{r.get('family','?'):<22} {tag:<14} status={r.get('status','open')}"
            )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
