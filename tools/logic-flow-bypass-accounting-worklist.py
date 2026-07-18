#!/usr/bin/env python3
"""Build a corpus-first worklist for accounting/value-flow logic bypasses.

This tool is intentionally not a detector. It inventories draft corpus rows
that look like the GainsNetwork-inspired accounting/value-flow subcase of
``logic-error-flow-bypass`` and records why they need source/value-flow evidence
before any Tier A detectorization claim.
"""
from __future__ import annotations

import argparse
import json
import re
import sys
from pathlib import Path
from typing import Any

try:
    import yaml
except ImportError:  # pragma: no cover - exercised only in stripped envs
    yaml = None  # type: ignore[assignment]


ROOT = Path(__file__).resolve().parents[1]
DEFAULT_SPEC_DIR = ROOT / "detectors" / "_specs" / "drafts_solodit"
SCHEMA_VERSION = "auditooor.logic_flow_bypass_accounting_worklist.v1"
BUG_CLASS = "logic-error-flow-bypass"
SUBCASE = "accounting_value_flow"

ACCOUNTING_RE = re.compile(
    r"\b(account(?:ing|ed)?|accru(?:e|al)|balance|debt|fee|collateral|"
    r"available\s+collateral|position|leverage|pnl|profit|loss|liquidit|"
    r"share|reserve|vault|credit|debit)\b",
    re.I,
)
VALUE_FLOW_RE = re.compile(
    r"\b(transfer|send|sent|withdraw|redeem|payout|pay|paid|drain|steal|"
    r"assets?|funds?|token|collateral|vault|trader|recipient|destination)\b",
    re.I,
)
BYPASS_RE = re.compile(
    r"\b(bypass|evade|avoid|skip|misdirect|double|twice|wrong|incorrect|"
    r"inconsistent|risk[- ]?free|not\s+(?:charged|paid|transferred|accounted)|"
    r"stale|missing|flawed)\b",
    re.I,
)
GAINS_SAMPLE_RE = re.compile(
    r"\b(GainsNetwork|executeDecreasePositionSizeMarket|collateralSentToTrader|partialNetPnlCollateral)\b",
    re.I,
)

SOURCE_SHAPE_LIMITATIONS = [
    "draft corpus text is not source-level exploitability proof",
    "no compiler-backed callgraph, value-flow graph, or runtime deployment proof is produced",
    "no vulnerable/clean fixture pair is proven by this worklist",
    "no severity, selected impact, PoC posture, or detector closure may be inferred",
]

REQUIRED_VALUE_FLOW_EVIDENCE = [
    "source function that mutates accounting state for the position/order/trader",
    "source function or callee that moves assets or chooses the recipient/destination",
    "data dependency between accounting amount and transferred/sent/withdrawn amount",
    "reachable bypass path showing the accounting/value-flow mismatch is externally exercisable",
    "paired vulnerable and clean fixtures before detector promotion",
]


def _load_yaml(path: Path) -> dict[str, Any] | None:
    if yaml is None:
        raise SystemExit("[logic-flow-bypass-accounting-worklist] PyYAML is required")
    try:
        loaded = yaml.safe_load(path.read_text(encoding="utf-8", errors="replace"))
    except (OSError, yaml.YAMLError) as exc:
        print(f"[logic-flow-bypass-accounting-worklist] skip unreadable yaml {path}: {exc}", file=sys.stderr)
        return None
    return loaded if isinstance(loaded, dict) else None


def _repo_rel(path: Path) -> str:
    try:
        return str(path.resolve().relative_to(ROOT))
    except ValueError:
        return str(path)


def _text(spec: dict[str, Any], *keys: str) -> str:
    parts: list[str] = []
    for key in keys:
        value = spec.get(key)
        if isinstance(value, str):
            parts.append(value)
        elif isinstance(value, list):
            parts.extend(str(item) for item in value if isinstance(item, (str, int, float)))
        elif isinstance(value, dict):
            parts.extend(str(item) for item in value.values() if isinstance(item, (str, int, float)))
    return "\n".join(parts)


def _matches(regex: re.Pattern[str], text: str) -> list[str]:
    seen: set[str] = set()
    out: list[str] = []
    for match in regex.finditer(text):
        value = re.sub(r"\s+", " ", match.group(0).strip()).lower()
        if value and value not in seen:
            seen.add(value)
            out.append(value)
    return out


def _slug(value: str, fallback: str = "row") -> str:
    slug = re.sub(r"[^a-z0-9]+", "-", value.lower()).strip("-")
    return (slug or fallback)[:96]


def _spec_title(spec: dict[str, Any], path: Path) -> str:
    for key in ("wiki_title", "help", "name", "title"):
        value = spec.get(key)
        if isinstance(value, str) and value.strip():
            return value.strip()
    return path.stem


def _classify_spec(path: Path, spec: dict[str, Any], index: int) -> dict[str, Any] | None:
    body = _text(
        spec,
        "source",
        "help",
        "wiki_title",
        "wiki_description",
        "wiki_exploit_scenario",
        "solodit_slug",
        "name",
    )
    accounting = _matches(ACCOUNTING_RE, body)
    value_flow = _matches(VALUE_FLOW_RE, body)
    bypass = _matches(BYPASS_RE, body)
    gains_inspired = bool(GAINS_SAMPLE_RE.search(body))
    if not (accounting and value_flow and bypass):
        return None

    title = _spec_title(spec, path)
    source = str(spec.get("source") or "")
    source_id = str(spec.get("solodit_id") or spec.get("name") or path.stem)
    row_slug = _slug(source_id if source_id else title)
    return {
        "row_id": f"LFB-ACT-{index:03d}-{row_slug}",
        "bug_class": BUG_CLASS,
        "subcase": SUBCASE,
        "source_path": _repo_rel(path),
        "source_id": source_id,
        "source": source,
        "title": title,
        "gains_network_inspired": gains_inspired,
        "matched_signals": {
            "accounting": accounting[:12],
            "value_flow": value_flow[:12],
            "bypass_or_mismatch": bypass[:12],
        },
        "action_lane": "corpus_first_value_flow_triage",
        "detectorization_readiness": "not_ready_needs_value_flow_corpus_evidence",
        "submission_posture": "NOT_SUBMIT_READY",
        "submit_status": "NOT_SUBMIT_READY",
        "severity": "none",
        "selected_impact": "",
        "impact_contract_required": True,
        "promotion_allowed": False,
        "tier_a_detector_closure_claim": False,
        "why_no_detector_yet": [
            "static name/call regexes cannot prove the accounting amount controls the asset movement",
            "the subcase depends on value-flow direction, recipient, signed/negative amount, or double-withdraw semantics",
            "clean behavior requires an adjacent source pattern, not only absence of GainsNetwork-like words",
        ],
        "required_value_flow_evidence": REQUIRED_VALUE_FLOW_EVIDENCE,
        "recommended_next_action": (
            "Collect source/corpus exemplars and derive a narrow predicate only after the "
            "accounting update, asset movement, reachable bypass path, and clean adjacent "
            "case are all visible."
        ),
    }


def build_worklist(spec_dir: Path, *, limit: int = 200) -> dict[str, Any]:
    candidates: list[dict[str, Any]] = []
    yaml_paths = sorted(path for path in spec_dir.rglob("*.yaml") if path.is_file())
    for path in yaml_paths:
        spec = _load_yaml(path)
        if spec is None:
            continue
        row = _classify_spec(path, spec, len(candidates) + 1)
        if row is not None:
            candidates.append(row)

    candidates.sort(key=lambda row: (not bool(row.get("gains_network_inspired")), str(row.get("title", ""))))
    rows = candidates[:limit]
    for idx, row in enumerate(rows, start=1):
        row["row_id"] = re.sub(r"^LFB-ACT-\d{3}-", f"LFB-ACT-{idx:03d}-", str(row["row_id"]))
    gains_rows = sum(1 for row in rows if row.get("gains_network_inspired"))
    return {
        "schema": SCHEMA_VERSION,
        "bug_class": BUG_CLASS,
        "subcase": SUBCASE,
        "spec_dir": _repo_rel(spec_dir),
        "corpus_first": True,
        "detectorization_posture": "CORPUS_FIRST",
        "actionable_detector_work": False,
        "promotion_allowed": False,
        "tier_a_detector_closure_claim": False,
        "coverage_claim": "none_worklist_only",
        "advisory_only": True,
        "source_shape_limitations": SOURCE_SHAPE_LIMITATIONS,
        "required_value_flow_evidence": REQUIRED_VALUE_FLOW_EVIDENCE,
        "scanned_yaml_count": len(yaml_paths),
        "task_count": len(rows),
        "gains_network_inspired_count": gains_rows,
        "non_gains_accounting_value_flow_count": len(rows) - gains_rows,
        "detectorization_readiness_counts": {
            "not_ready_needs_value_flow_corpus_evidence": len(rows),
        },
        "tasks": rows,
        "next_actions": [
            "mine source/corpus examples with explicit accounting update plus asset movement",
            "separate double-withdraw, signed-PnL/destination, fee-accounting, and stale-available-balance shapes",
            "only prototype a detector for one shape after vulnerable and clean fixtures are structurally proven",
        ],
    }


def render_markdown(payload: dict[str, Any]) -> str:
    lines = [
        "# Logic Flow Bypass Accounting Worklist",
        "",
        "Corpus-first inventory for accounting/value-flow `logic-error-flow-bypass` rows.",
        "This is not detector closure and does not imply exploitability.",
        "",
        f"- schema: `{payload['schema']}`",
        f"- posture: `{payload['detectorization_posture']}`",
        f"- task count: {payload['task_count']}",
        f"- GainsNetwork-inspired rows: {payload['gains_network_inspired_count']}",
        f"- actionable detector work: `{str(payload['actionable_detector_work']).lower()}`",
        f"- promotion allowed: `{str(payload['promotion_allowed']).lower()}`",
        "",
        "## Required Evidence",
        "",
    ]
    for item in payload.get("required_value_flow_evidence", []):
        lines.append(f"- {item}")
    lines.extend(["", "## Tasks", ""])
    tasks = payload.get("tasks") if isinstance(payload.get("tasks"), list) else []
    if not tasks:
        lines.append("_No accounting/value-flow worklist rows matched._")
        return "\n".join(lines) + "\n"
    lines.append("| Row | Gains | Source | Readiness | Reason |")
    lines.append("|---|---:|---|---|---|")
    for task in tasks[:200]:
        reason = "; ".join(task.get("why_no_detector_yet", [])[:2])
        lines.append(
            "| `{}` | `{}` | `{}` | `{}` | {} |".format(
                task.get("row_id", ""),
                str(bool(task.get("gains_network_inspired"))).lower(),
                task.get("title", ""),
                task.get("detectorization_readiness", ""),
                reason,
            )
        )
    return "\n".join(lines) + "\n"


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--spec-dir", type=Path, default=DEFAULT_SPEC_DIR)
    parser.add_argument("--out-json", type=Path)
    parser.add_argument("--out-md", type=Path)
    parser.add_argument("--limit", type=int, default=200)
    parser.add_argument("--print-json", action="store_true")
    args = parser.parse_args(argv)

    spec_dir = args.spec_dir.expanduser().resolve()
    if not spec_dir.is_dir():
        print(f"[logic-flow-bypass-accounting-worklist] spec dir not found: {spec_dir}", file=sys.stderr)
        return 2

    payload = build_worklist(spec_dir, limit=max(0, args.limit))
    if args.out_json:
        args.out_json.parent.mkdir(parents=True, exist_ok=True)
        args.out_json.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    if args.out_md:
        args.out_md.parent.mkdir(parents=True, exist_ok=True)
        args.out_md.write_text(render_markdown(payload), encoding="utf-8")
    if args.print_json:
        print(json.dumps(payload, indent=2, sort_keys=True))
    print(
        "[logic-flow-bypass-accounting-worklist] OK "
        f"tasks={payload['task_count']} posture={payload['detectorization_posture']}",
        file=sys.stderr,
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
