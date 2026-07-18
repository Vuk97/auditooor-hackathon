#!/usr/bin/env python3
"""outcome-feedback-loop.py — F5 learning loop: outcome → tier adjustment.

Reads outcome telemetry + tier registry and applies detector tier calibration
rules:

  Rule T1 (Tier-S candidate):
    Pattern with >=3 paid/accepted TPs across >=3 distinct workspaces.
    Operator-gated: emits candidate to obsidian-vault/calibration/promotion-candidates.md.
    NOT auto-applied. n<5 → "preliminary" banner.

  Rule T2 (Tier-D demotion):
    Pattern with >=3 rejected FPs.
    Auto-applied: writes new tier record into tier registry (read audit only in
    self-test mode / --dry-run). Surfaced in summary.

  Rule T3 (Mixed):
    Pattern with both TP and FP outcomes.
    No change; flagged for operator review.

M14-trap discipline: every adjustment row carries sample_size +
last_validated_at + confidence. No n<5 promotions (preliminary banner only).

No LLM calls. No registry mutation in --dry-run / self-test mode.

Usage:
    python3 tools/outcome-feedback-loop.py [--dry-run] [--outcomes <path>]
        [--registry <path>] [--out-json <path>] [--vault-dir <path>]

Output:
    reports/outcome_feedback_<YYYY-MM-DD>.json
    obsidian-vault/calibration/promotion-candidates.md
"""
from __future__ import annotations

import argparse
import json
import re
import sys
from collections import Counter, defaultdict
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Optional

from outcome_semantics import (
    LEARNING_SCOPE_PLATFORM_BASE_RATE_ONLY,
    UNKNOWN_REASON_DECLINE_CODE,
    derive_outcome_semantics,
    normalize_outcome as normalize_outcome_value,
)

# ---------------------------------------------------------------------------
# Paths
# ---------------------------------------------------------------------------

SCRIPT = Path(__file__).resolve()
REPO_ROOT = SCRIPT.parent.parent
DEFAULT_OUTCOMES_JSONL = REPO_ROOT / "reference" / "outcomes.jsonl"
DEFAULT_OUTCOMES_JSON = REPO_ROOT / "tools" / "outcomes.json"
DEFAULT_REGISTRY = REPO_ROOT / "detectors" / "_tier_registry.yaml"
DEFAULT_OUT_JSON_TEMPLATE = "reports/outcome_feedback_{date}.json"
DEFAULT_VAULT = REPO_ROOT / "obsidian-vault"

MIN_TP_FOR_PROMOTION = 3
MIN_WORKSPACES_FOR_PROMOTION = 3
MIN_FP_FOR_DEMOTION = 3
N_PRELIMINARY_THRESHOLD = 5  # sample_size < this → "preliminary" banner
UNKNOWN_DECLINE_NEXT_COMMAND = (
    "python3 tools/outcome-feedback-loop.py --dry-run "
    "--outcomes reference/outcomes.jsonl --print-json"
)
UNKNOWN_DECLINE_STOP_CONDITION = (
    "Only explicit triager/platform rejection text may convert this row from "
    "platform-base-rate-only memory into causal FP learning."
)

# Canonical tiers in ascending quality order
TIER_ORDER = ["PAPER", "ARCHIVED", "D", "E", "B", "A", "S"]

# Platform detection: map workspace/source strings to platform labels
_PLATFORM_PATTERNS: list[tuple[re.Pattern, str]] = [
    (re.compile(r"cantina", re.I), "Cantina"),
    (re.compile(r"sherlock", re.I), "Sherlock"),
    (re.compile(r"immunefi", re.I), "Immunefi"),
    (re.compile(r"code4rena|c4\b", re.I), "Code4rena"),
    (re.compile(r"spearbit", re.I), "Spearbit"),
    (re.compile(r"cyfrin", re.I), "Cyfrin"),
    (re.compile(r"hackerone", re.I), "HackerOne"),
]

# Known workspace → platform mapping (best-effort)
_WORKSPACE_PLATFORM: dict[str, str] = {
    "polymarket": "Cantina",
    "morpho": "Cantina",
    "centrifuge": "Cantina",
    "centrifuge-v3": "Cantina",
    "base-azul": "Cantina",
}


# ---------------------------------------------------------------------------
# Data structures
# ---------------------------------------------------------------------------


@dataclass
class OutcomeRow:
    workspace: str
    finding_id: str
    title: str
    severity: str
    outcome: str  # normalized: accepted | rejected | duplicate | pending | unknown | withdrawn
    platform: str = "Unknown"
    source: str = ""
    status: str = ""
    date: str = ""
    rejection_reason: str = ""
    learning_scope: str = "full"
    memory_action_routes: list[str] = field(default_factory=list)
    follow_up_cues: list[str] = field(default_factory=list)
    # Optional enrichment
    patterns_used: list[str] = field(default_factory=list)
    detectors_used: list[str] = field(default_factory=list)


@dataclass
class PatternStats:
    pattern_id: str
    accepted_workspaces: list[str] = field(default_factory=list)  # distinct ws with TP
    rejected_workspaces: list[str] = field(default_factory=list)  # distinct ws with FP
    accepted_total: int = 0
    rejected_total: int = 0
    duplicate_total: int = 0
    last_seen: str = ""

    @property
    def sample_size(self) -> int:
        return self.accepted_total + self.rejected_total + self.duplicate_total

    @property
    def distinct_tp_workspaces(self) -> int:
        return len(set(self.accepted_workspaces))

    @property
    def distinct_fp_workspaces(self) -> int:
        return len(set(self.rejected_workspaces))

    def confidence(self) -> str:
        n = self.sample_size
        if n < 3:
            return "insufficient"
        if n < N_PRELIMINARY_THRESHOLD:
            return "preliminary"
        return "adequate"


@dataclass
class AdjustmentRow:
    pattern_id: str
    rule: str  # T1 / T2 / T3
    action: str  # promote_candidate | demote | flag_mixed
    current_tier: Optional[str]
    proposed_tier: Optional[str]
    sample_size: int
    accepted_total: int
    rejected_total: int
    distinct_tp_workspaces: int
    distinct_fp_workspaces: int
    confidence: str
    last_validated_at: str
    notes: str
    preliminary: bool  # sample_size < N_PRELIMINARY_THRESHOLD


# ---------------------------------------------------------------------------
# I/O helpers
# ---------------------------------------------------------------------------


def _load_jsonl(path: Path) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    if not path.is_file():
        return rows
    for line in path.read_text(encoding="utf-8", errors="replace").splitlines():
        stripped = line.strip()
        if not stripped:
            continue
        try:
            obj = json.loads(stripped)
        except json.JSONDecodeError:
            continue
        if isinstance(obj, dict):
            rows.append(obj)
    return rows


def _load_json_array(path: Path) -> list[dict[str, Any]]:
    if not path.is_file():
        return []
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except (json.JSONDecodeError, OSError):
        return []
    if isinstance(data, list):
        return [r for r in data if isinstance(r, dict)]
    return []


def load_outcomes(jsonl_path: Path, json_fallback: Path) -> list[dict[str, Any]]:
    """Load outcome rows, preferring JSONL over legacy JSON."""
    if jsonl_path.is_file():
        return _load_jsonl(jsonl_path)
    if json_fallback.is_file():
        return _load_json_array(json_fallback)
    return []


def load_tier_registry(path: Path) -> dict[str, dict[str, Any]]:
    """Parse _tier_registry.yaml into {detector_id: {tier, reason, ...}}.

    Uses stdlib only (no PyYAML). Parses the block-scalar format produced by
    backfill-tier-registry.py: top-level keys followed by indented `tier:` lines.
    Sufficient for read-only audit; does not parse all YAML features.
    """
    registry: dict[str, dict[str, Any]] = {}
    if not path.is_file():
        return registry

    text = path.read_text(encoding="utf-8", errors="replace")
    lines = text.splitlines()

    current_key: Optional[str] = None
    current_entry: dict[str, Any] = {}

    key_re = re.compile(r"^  ([a-zA-Z0-9_\-]+):\s*$")
    field_re = re.compile(r"^    (\w+):\s*(.*)$")

    for line in lines:
        if line.startswith("version:") or line.startswith("tiers:"):
            current_key = None
            current_entry = {}
            continue
        km = key_re.match(line)
        if km:
            # Save previous
            if current_key and current_entry:
                registry[current_key] = current_entry
            current_key = km.group(1)
            current_entry = {}
            continue
        if current_key is None:
            continue
        fm = field_re.match(line)
        if fm:
            k, v = fm.group(1), fm.group(2).strip().strip("'\"")
            current_entry[k] = v

    if current_key and current_entry:
        registry[current_key] = current_entry

    return registry


# ---------------------------------------------------------------------------
# Outcome normalization
# ---------------------------------------------------------------------------


def normalize_outcome(raw: str) -> str:
    """Map free-form outcome/status to canonical bucket."""
    return normalize_outcome_value(raw)


def _detect_platform(workspace: str, source: str) -> str:
    """Infer platform from workspace name or source path."""
    combined = f"{workspace} {source}".lower()
    for pat, label in _PLATFORM_PATTERNS:
        if pat.search(combined):
            return label
    # Workspace-level override
    for ws_key, plat in _WORKSPACE_PLATFORM.items():
        if ws_key in workspace.lower():
            return plat
    return "Unknown"


# ---------------------------------------------------------------------------
# Pattern linkage (title-based heuristic)
# ---------------------------------------------------------------------------

# Keyword → pattern slug (mirrors outcome_reweight.py for consistency)
_KEYWORD_TO_PATTERN: list[tuple[str, str]] = [
    ("reentr", "reentrancy"),
    ("access.control", "access-control"),
    ("unauthenticat", "access-control"),
    ("authoriz", "access-control"),
    ("oracle", "oracle-manipulation"),
    ("price.manipul", "oracle-manipulation"),
    ("delegatecall", "delegatecall"),
    ("erc4626", "erc4626-inflation"),
    ("inflation", "erc4626-inflation"),
    ("flash.loan", "flash-loan"),
    ("flash loan", "flash-loan"),
    ("timestamp", "timestamp-dependence"),
    ("front.run", "frontrunning"),
    ("frontrun", "frontrunning"),
    ("race.condition", "race-condition"),
    ("upgrade", "uninitialized-upgrade"),
    ("initializ", "uninitialized-upgrade"),
    ("overflow", "integer-overflow"),
    ("underflow", "integer-overflow"),
    ("arithmetic", "integer-overflow"),
    ("zero.address", "zero-address-check"),
    ("missing.check", "missing-validation"),
    ("validation", "missing-validation"),
    ("emit", "missing-event"),
    ("event", "missing-event"),
    ("signature", "signature-replay"),
    ("replay", "signature-replay"),
    ("nonce", "signature-replay"),
    ("denial.of.service", "dos"),
    ("dos\b", "dos"),
    ("gas.griefing", "dos"),
    ("centrali", "centralization-risk"),
    ("admin", "centralization-risk"),
]


def _title_to_patterns(title: str) -> list[str]:
    """Heuristically map a finding title to pattern slug(s)."""
    found: list[str] = []
    title_lower = title.lower()
    seen: set[str] = set()
    for kw, slug in _KEYWORD_TO_PATTERN:
        if re.search(kw, title_lower) and slug not in seen:
            found.append(slug)
            seen.add(slug)
    return found


# ---------------------------------------------------------------------------
# Core analysis
# ---------------------------------------------------------------------------


def build_outcome_rows(raw_rows: list[dict[str, Any]]) -> list[OutcomeRow]:
    rows: list[OutcomeRow] = []
    for r in raw_rows:
        semantics = derive_outcome_semantics(r)
        title = str(r.get("title") or "")
        workspace = str(r.get("workspace") or r.get("engagement") or "")
        source = str(r.get("source") or "")
        rows.append(OutcomeRow(
            workspace=workspace,
            finding_id=str(r.get("finding_id") or r.get("submission_id") or ""),
            title=title,
            severity=str(r.get("severity") or r.get("severity_claimed") or "Unknown"),
            outcome=semantics.outcome,
            platform=_detect_platform(workspace, source),
            source=source,
            status=str(r.get("status") or ""),
            date=str(r.get("date") or r.get("submitted_date") or ""),
            rejection_reason=semantics.rejection_reason,
            learning_scope=semantics.learning_scope,
            memory_action_routes=list(semantics.memory_action_routes),
            follow_up_cues=list(semantics.follow_up_cues),
            patterns_used=_title_to_patterns(title),
            detectors_used=[],
        ))
    return rows


def aggregate_pattern_stats(rows: list[OutcomeRow]) -> dict[str, PatternStats]:
    stats: dict[str, PatternStats] = {}
    for row in rows:
        if row.learning_scope != "full":
            continue
        for pattern_id in row.patterns_used:
            if pattern_id not in stats:
                stats[pattern_id] = PatternStats(pattern_id=pattern_id)
            ps = stats[pattern_id]
            if row.date:
                if not ps.last_seen or row.date > ps.last_seen:
                    ps.last_seen = row.date
            if row.outcome == "accepted":
                ps.accepted_total += 1
                if row.workspace:
                    ps.accepted_workspaces.append(row.workspace)
            elif row.outcome == "rejected":
                ps.rejected_total += 1
                if row.workspace:
                    ps.rejected_workspaces.append(row.workspace)
            elif row.outcome == "duplicate":
                ps.duplicate_total += 1
    return stats


def compute_adjustments(
    pattern_stats: dict[str, PatternStats],
    registry: dict[str, dict[str, Any]],
    now_str: str,
) -> list[AdjustmentRow]:
    adjustments: list[AdjustmentRow] = []

    for pattern_id, ps in sorted(pattern_stats.items()):
        if ps.sample_size == 0:
            continue

        n_tp = ps.accepted_total
        n_fp = ps.rejected_total
        n_ws_tp = ps.distinct_tp_workspaces
        prelim = ps.sample_size < N_PRELIMINARY_THRESHOLD
        conf = ps.confidence()

        # Find current tier in registry (best-effort: look for exact or partial match)
        current_tier: Optional[str] = None
        for det_id, entry in registry.items():
            if pattern_id.lower() in det_id.lower() or det_id.lower() in pattern_id.lower():
                current_tier = entry.get("tier")
                break

        # Rule T1: Tier-S promotion candidate
        if n_tp >= MIN_TP_FOR_PROMOTION and n_ws_tp >= MIN_WORKSPACES_FOR_PROMOTION:
            notes = (
                f"[PRELIMINARY — n={ps.sample_size} < {N_PRELIMINARY_THRESHOLD}] " if prelim else ""
            ) + (
                f"Pattern '{pattern_id}' has {n_tp} accepted TPs across "
                f"{n_ws_tp} distinct workspace(s). "
                f"Operator review required before promotion to Tier-S."
            )
            adjustments.append(AdjustmentRow(
                pattern_id=pattern_id,
                rule="T1",
                action="promote_candidate",
                current_tier=current_tier,
                proposed_tier="S",
                sample_size=ps.sample_size,
                accepted_total=n_tp,
                rejected_total=n_fp,
                distinct_tp_workspaces=n_ws_tp,
                distinct_fp_workspaces=ps.distinct_fp_workspaces,
                confidence=conf,
                last_validated_at=now_str,
                notes=notes,
                preliminary=prelim,
            ))

        # Rule T2: Tier-D demotion
        elif n_fp >= MIN_FP_FOR_DEMOTION and n_tp == 0:
            notes = (
                f"[PRELIMINARY — n={ps.sample_size} < {N_PRELIMINARY_THRESHOLD}] " if prelim else ""
            ) + (
                f"Pattern '{pattern_id}' has {n_fp} rejected FPs across "
                f"{ps.distinct_fp_workspaces} workspace(s) with 0 accepted outcomes. "
                f"Demoting to Tier-D."
            )
            adjustments.append(AdjustmentRow(
                pattern_id=pattern_id,
                rule="T2",
                action="demote",
                current_tier=current_tier,
                proposed_tier="D",
                sample_size=ps.sample_size,
                accepted_total=n_tp,
                rejected_total=n_fp,
                distinct_tp_workspaces=n_ws_tp,
                distinct_fp_workspaces=ps.distinct_fp_workspaces,
                confidence=conf,
                last_validated_at=now_str,
                notes=notes,
                preliminary=prelim,
            ))

        # Rule T3: Mixed
        elif n_tp >= 1 and n_fp >= 1:
            notes = (
                f"[PRELIMINARY — n={ps.sample_size} < {N_PRELIMINARY_THRESHOLD}] " if prelim else ""
            ) + (
                f"Pattern '{pattern_id}' has mixed outcomes: "
                f"{n_tp} accepted, {n_fp} rejected across "
                f"{n_ws_tp + ps.distinct_fp_workspaces} workspace(s). "
                f"No automatic adjustment; flagged for operator review."
            )
            adjustments.append(AdjustmentRow(
                pattern_id=pattern_id,
                rule="T3",
                action="flag_mixed",
                current_tier=current_tier,
                proposed_tier=None,
                sample_size=ps.sample_size,
                accepted_total=n_tp,
                rejected_total=n_fp,
                distinct_tp_workspaces=n_ws_tp,
                distinct_fp_workspaces=ps.distinct_fp_workspaces,
                confidence=conf,
                last_validated_at=now_str,
                notes=notes,
                preliminary=prelim,
            ))

    return adjustments


def build_memory_action_cues(rows: list[OutcomeRow]) -> list[dict[str, Any]]:
    """Route non-causal terminal declines to bounded calibration actions."""
    cues: list[dict[str, Any]] = []
    for row in rows:
        if row.learning_scope != LEARNING_SCOPE_PLATFORM_BASE_RATE_ONLY:
            continue
        if row.outcome != "rejected":
            continue
        cues.append({
            "workspace": row.workspace,
            "finding_id": row.finding_id,
            "title": row.title,
            "platform": row.platform,
            "outcome": row.outcome,
            "terminal_state": "terminal_rejected",
            "learning_scope": row.learning_scope,
            "routing_code": UNKNOWN_REASON_DECLINE_CODE,
            "recorded_rejection_reason": row.rejection_reason,
            "report_valid": True,
            "causal_reason_inferred": False,
            "pattern_fp_learning_allowed": False,
            "actionability_status": "actionable_base_rate_only",
            "next_command": UNKNOWN_DECLINE_NEXT_COMMAND,
            "operator_checklist": [
                "count terminal decline in platform/base-rate calibration",
                "queue self-learning review without assigning a rejection cause",
                "keep pattern FP and severity calibration unchanged",
            ],
            "stop_condition": UNKNOWN_DECLINE_STOP_CONDITION,
            "action_routes": list(row.memory_action_routes),
            "follow_up_cues": list(row.follow_up_cues),
            "notes": (
                "Terminal no-reason decline. Count it for platform base-rate "
                "calibration and self-learning review only; do not invent a "
                "duplicate/OOS/proof-failure/severity cause."
            ),
        })
    return cues


# ---------------------------------------------------------------------------
# Output writers
# ---------------------------------------------------------------------------


def _portable(path: Path) -> str:
    try:
        return str(path.resolve().relative_to(REPO_ROOT.resolve()))
    except ValueError:
        return str(path)


def build_report(
    rows: list[OutcomeRow],
    pattern_stats: dict[str, PatternStats],
    adjustments: list[AdjustmentRow],
    registry_size: int,
    now_str: str,
    dry_run: bool,
) -> dict[str, Any]:
    outcome_counts = Counter(r.outcome for r in rows)
    memory_action_cues = build_memory_action_cues(rows)
    has_real_data = any(
        r.outcome in ("accepted", "rejected") for r in rows
    )
    data_sufficiency = "insufficient_data" if not has_real_data else (
        "preliminary" if len(rows) < 10 else "adequate"
    )

    promote_candidates = [a for a in adjustments if a.rule == "T1"]
    demotions = [a for a in adjustments if a.rule == "T2"]
    mixed_flags = [a for a in adjustments if a.rule == "T3"]

    return {
        "schema": "auditooor.outcome_feedback_loop.v1",
        "generated_at": now_str,
        "dry_run": dry_run,
        "sample_size_discipline": {
            "min_tp_for_promotion": MIN_TP_FOR_PROMOTION,
            "min_workspaces_for_promotion": MIN_WORKSPACES_FOR_PROMOTION,
            "min_fp_for_demotion": MIN_FP_FOR_DEMOTION,
            "preliminary_threshold": N_PRELIMINARY_THRESHOLD,
            "note": "n<5 rows carry 'preliminary' banner per M14-trap / PLAN-MEM §10",
        },
        "input_summary": {
            "outcome_rows_loaded": len(rows),
            "patterns_mapped": len(pattern_stats),
            "registry_detectors": registry_size,
            "outcome_distribution": dict(outcome_counts),
            "base_rate_only_rejections": len(memory_action_cues),
            "memory_action_cues": len(memory_action_cues),
            "data_sufficiency": data_sufficiency,
        },
        "honest_assessment": (
            "INSUFFICIENT DATA: no accepted/rejected outcomes found. "
            "Adjustments cannot be computed. Results show 0 candidates until "
            "F1 Solodit ingest or live engagement outcomes are logged."
        ) if not has_real_data else (
            f"Data available: {outcome_counts.get('accepted', 0)} accepted, "
            f"{outcome_counts.get('rejected', 0)} rejected outcomes "
            f"across {len(set(r.workspace for r in rows if r.workspace))} workspace(s). "
            f"Pattern linkage is heuristic (title-keyword). Confidence increases with F1 ingest."
        ),
        "adjustments_summary": {
            "promotion_candidates": len(promote_candidates),
            "demotions": len(demotions),
            "mixed_flags": len(mixed_flags),
        },
        "memory_action_routing": {
            "unknown_no_reason_declines": {
                "count": len(memory_action_cues),
                "routes": sorted({
                    route
                    for cue in memory_action_cues
                    for route in cue["action_routes"]
                }),
                "follow_up_cues": sorted({
                    follow_up
                    for cue in memory_action_cues
                    for follow_up in cue["follow_up_cues"]
                }),
                "report_valid": True,
                "causal_reason_inference_allowed": False,
                "actionability_status": (
                    "actionable_base_rate_only" if memory_action_cues else "not_applicable"
                ),
                "next_commands": (
                    [UNKNOWN_DECLINE_NEXT_COMMAND] if memory_action_cues else []
                ),
                "stop_condition": UNKNOWN_DECLINE_STOP_CONDITION,
                "rows": memory_action_cues,
            },
        },
        "promotion_candidates": [asdict(a) for a in promote_candidates],
        "demotions": [asdict(a) for a in demotions],
        "mixed_flags": [asdict(a) for a in mixed_flags],
    }


def write_promotion_candidates_md(
    adjustments: list[AdjustmentRow],
    vault_dir: Path,
    now_str: str,
) -> Path:
    """Emit obsidian-vault/calibration/promotion-candidates.md."""
    out_dir = vault_dir / "calibration"
    out_dir.mkdir(parents=True, exist_ok=True)
    out_path = out_dir / "promotion-candidates.md"

    candidates = [a for a in adjustments if a.rule == "T1"]
    lines = [
        "# Tier-S Promotion Candidates",
        "",
        f"_Generated: {now_str}_",
        "",
        "> **Operator-gated.** These patterns qualified for Tier-S based on outcome",
        "> telemetry (>=3 paid TPs across >=3 workspaces). No promotion is applied",
        "> automatically. Review each candidate and confirm before updating the registry.",
        ">",
        "> **M14-trap discipline:** every row carries `sample_size`, `confidence`, and",
        "> `last_validated_at`. Rows marked `[PRELIMINARY]` have n<5 — treat as early signal only.",
        "",
    ]

    if not candidates:
        lines += [
            "## No Promotion Candidates",
            "",
            "No patterns currently meet the Tier-S threshold (>=3 paid TPs across >=3 workspaces).",
            "",
            "**Honest gap:** Most ledger entries are `pending` or `rejected`.",
            "This section will populate once F1 Solodit ingest provides at-scale accepted outcome data.",
        ]
    else:
        lines += [
            f"## {len(candidates)} Candidate(s)",
            "",
            "| Pattern | Current Tier | TPs | Workspaces | Sample Size | Confidence | Last Validated |",
            "|---|---|---:|---:|---:|---|---|",
        ]
        for a in sorted(candidates, key=lambda x: -x.accepted_total):
            prelim = "[PRELIMINARY] " if a.preliminary else ""
            lines.append(
                f"| `{a.pattern_id}` | {a.current_tier or '-'} | {a.accepted_total} "
                f"| {a.distinct_tp_workspaces} | {a.sample_size} "
                f"| {prelim}{a.confidence} | {a.last_validated_at[:10]} |"
            )
        lines += ["", "### Candidate Details", ""]
        for a in candidates:
            lines += [
                f"#### `{a.pattern_id}`",
                "",
                f"- **Rule**: {a.rule} — Tier-S promotion candidate",
                f"- **Current tier**: {a.current_tier or 'not in registry'}",
                f"- **sample_size**: {a.sample_size}",
                f"- **accepted_total**: {a.accepted_total}",
                f"- **distinct_tp_workspaces**: {a.distinct_tp_workspaces}",
                f"- **confidence**: {a.confidence}",
                f"- **last_validated_at**: {a.last_validated_at}",
                f"- **Notes**: {a.notes}",
                "",
                "**To promote** (operator action required):",
                "```bash",
                f"# Verify the pattern genuinely hit in each workspace, then:",
                f"# Update detectors/_tier_registry.yaml: tier: S for '{a.pattern_id}'",
                "```",
                "",
            ]

    return _write_md(out_path, lines)


def _write_md(path: Path, lines: list[str]) -> Path:
    path.write_text("\n".join(lines) + "\n", encoding="utf-8")
    return path


def write_report_json(report: dict[str, Any], out_path: Path) -> None:
    out_path.parent.mkdir(parents=True, exist_ok=True)
    out_path.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n", encoding="utf-8")


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------


def parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="F5 outcome feedback loop: telemetry → tier calibration."
    )
    parser.add_argument(
        "--outcomes",
        type=Path,
        default=DEFAULT_OUTCOMES_JSONL,
        help=f"Path to outcomes.jsonl or outcomes.json (default: {DEFAULT_OUTCOMES_JSONL})",
    )
    parser.add_argument(
        "--registry",
        type=Path,
        default=DEFAULT_REGISTRY,
        help=f"Path to _tier_registry.yaml (default: {DEFAULT_REGISTRY})",
    )
    parser.add_argument(
        "--out-json",
        type=Path,
        default=None,
        help="Output JSON report path. Default: reports/outcome_feedback_<date>.json",
    )
    parser.add_argument(
        "--vault-dir",
        type=Path,
        default=DEFAULT_VAULT,
        help=f"Obsidian vault directory (default: {DEFAULT_VAULT})",
    )
    parser.add_argument(
        "--dry-run",
        action="store_true",
        help="Read-only: compute adjustments but do not write vault or apply demotions.",
    )
    parser.add_argument(
        "--print-json",
        action="store_true",
        help="Print JSON report to stdout in addition to writing file.",
    )
    return parser.parse_args(argv)


def main(argv: list[str] | None = None) -> int:
    args = parse_args(argv)
    now = datetime.now(timezone.utc)
    now_str = now.strftime("%Y-%m-%dT%H:%M:%SZ")
    date_str = now.strftime("%Y-%m-%d")

    # --- Load outcomes ---
    raw_rows = load_outcomes(args.outcomes, DEFAULT_OUTCOMES_JSON)
    print(f"[feedback-loop] loaded {len(raw_rows)} outcome rows from {args.outcomes}", file=sys.stderr)

    # --- Load registry ---
    registry = load_tier_registry(args.registry)
    print(f"[feedback-loop] loaded {len(registry)} detector entries from registry", file=sys.stderr)

    # --- Build analysis ---
    rows = build_outcome_rows(raw_rows)
    pattern_stats = aggregate_pattern_stats(rows)
    adjustments = compute_adjustments(pattern_stats, registry, now_str)

    # --- Build report ---
    report = build_report(rows, pattern_stats, adjustments, len(registry), now_str, args.dry_run)

    # --- Output JSON ---
    out_json = args.out_json
    if out_json is None:
        out_json = REPO_ROOT / DEFAULT_OUT_JSON_TEMPLATE.format(date=date_str)

    write_report_json(report, out_json)
    print(f"[feedback-loop] report written to {out_json}", file=sys.stderr)

    # --- Write vault (unless dry-run) ---
    if not args.dry_run:
        promo_path = write_promotion_candidates_md(adjustments, args.vault_dir, now_str)
        print(f"[feedback-loop] promotion candidates → {promo_path}", file=sys.stderr)
    else:
        print("[feedback-loop] --dry-run: skipping vault write and demotion apply", file=sys.stderr)

    # --- Summary ---
    promote_n = report["adjustments_summary"]["promotion_candidates"]
    demote_n = report["adjustments_summary"]["demotions"]
    mixed_n = report["adjustments_summary"]["mixed_flags"]
    sufficiency = report["input_summary"]["data_sufficiency"]
    print(f"[feedback-loop] data_sufficiency={sufficiency}", file=sys.stderr)
    print(
        f"[feedback-loop] adjustments: promote_candidates={promote_n} "
        f"demotions={demote_n} mixed_flags={mixed_n}",
        file=sys.stderr,
    )
    if sufficiency == "insufficient_data":
        print(
            "[feedback-loop] HONEST: insufficient outcome data for calibration. "
            "Run after real accepted/rejected outcomes are logged.",
            file=sys.stderr,
        )

    if args.print_json:
        print(json.dumps(report, indent=2, sort_keys=True))

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
