#!/usr/bin/env python3
"""per-platform-precision.py — F5 per-platform TP/FP/UNK precision tracker.

Reads outcome telemetry (reference/outcomes.jsonl or tools/outcomes.json) and
computes per-platform × per-pattern precision breakdowns:

  Platforms tracked:
    Cantina, Sherlock, Immunefi, Code4rena, Spearbit, Cyfrin, HackerOne

  Per-platform metrics:
    - total findings
    - accepted / rejected / duplicate / in_review / pending / unknown
    - precision = accepted / (accepted + rejected) — only when n_resolved >= 3
    - per-pattern TP/FP/UNK breakdown

M14-trap discipline: every row carries sample_size, last_validated_at, confidence.
n<3 resolved → precision = null (insufficient data).

Outputs:
    docs/PER_PLATFORM_PRECISION_<YYYY-MM-DD>.md
    obsidian-vault/calibration/per-platform/<platform>.md  (one per platform)

Usage:
    python3 tools/per-platform-precision.py [--outcomes <path>]
        [--out-md <path>] [--vault-dir <path>] [--print-json]
"""
from __future__ import annotations

import argparse
import json
import re
import sys
from collections import Counter, defaultdict
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Optional

from outcome_semantics import derive_outcome_semantics, normalize_outcome as normalize_outcome_value

# ---------------------------------------------------------------------------
# Paths
# ---------------------------------------------------------------------------

SCRIPT = Path(__file__).resolve()
REPO_ROOT = SCRIPT.parent.parent
DEFAULT_OUTCOMES_JSONL = REPO_ROOT / "reference" / "outcomes.jsonl"
DEFAULT_OUTCOMES_JSON = REPO_ROOT / "tools" / "outcomes.json"
DEFAULT_VAULT = REPO_ROOT / "obsidian-vault"
DEFAULT_DOCS_DIR = REPO_ROOT / "docs"

MIN_RESOLVED_FOR_PRECISION = 3  # n < this → precision = null

# Platform detection patterns (ordered: most specific first)
_PLATFORM_PATTERNS: list[tuple[re.Pattern, str]] = [
    (re.compile(r"cantina", re.I), "Cantina"),
    (re.compile(r"sherlock", re.I), "Sherlock"),
    (re.compile(r"immunefi", re.I), "Immunefi"),
    (re.compile(r"code4rena|c4\b", re.I), "Code4rena"),
    (re.compile(r"spearbit", re.I), "Spearbit"),
    (re.compile(r"cyfrin", re.I), "Cyfrin"),
    (re.compile(r"hackerone", re.I), "HackerOne"),
]

# Known workspace → platform (best-effort override)
_WORKSPACE_PLATFORM: dict[str, str] = {
    "polymarket": "Cantina",
    "morpho": "Cantina",
    "centrifuge": "Cantina",
    "centrifuge-v3": "Cantina",
    "base-azul": "Cantina",
}

# Pattern extraction (title keyword → slug)
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
    (r"dos\b", "dos"),
    ("gas.griefing", "dos"),
    ("centrali", "centralization-risk"),
    ("admin", "centralization-risk"),
]

ALL_PLATFORMS = [
    "Cantina", "Sherlock", "Immunefi", "Code4rena",
    "Spearbit", "Cyfrin", "HackerOne", "Unknown",
]


# ---------------------------------------------------------------------------
# Data structures
# ---------------------------------------------------------------------------


@dataclass
class FindingRow:
    platform: str
    workspace: str
    finding_id: str
    title: str
    severity: str
    outcome: str  # normalized: accepted | rejected | duplicate | in_review | pending | unknown | withdrawn
    status: str = ""
    date: str = ""
    learning_scope: str = "full"
    patterns: list[str] = field(default_factory=list)


@dataclass
class PatternPrecision:
    pattern_id: str
    platform: str
    accepted: int = 0
    rejected: int = 0
    unknown: int = 0  # pending / in_review / duplicate
    sample_size: int = 0
    last_seen: str = ""

    def precision(self) -> Optional[float]:
        resolved = self.accepted + self.rejected
        if resolved < MIN_RESOLVED_FOR_PRECISION:
            return None
        return self.accepted / resolved

    def confidence(self) -> str:
        resolved = self.accepted + self.rejected
        if resolved < MIN_RESOLVED_FOR_PRECISION:
            return "insufficient"
        if resolved < 5:
            return "preliminary"
        return "adequate"


@dataclass
class PlatformStats:
    platform: str
    total: int = 0
    accepted: int = 0
    rejected: int = 0
    duplicate: int = 0
    in_review: int = 0
    pending: int = 0
    unknown_outcome: int = 0
    withdrawn: int = 0
    pattern_rows: list[PatternPrecision] = field(default_factory=list)
    last_validated_at: str = ""

    @property
    def resolved(self) -> int:
        return self.accepted + self.rejected

    def precision(self) -> Optional[float]:
        if self.resolved < MIN_RESOLVED_FOR_PRECISION:
            return None
        return self.accepted / self.resolved

    def confidence(self) -> str:
        if self.resolved < MIN_RESOLVED_FOR_PRECISION:
            return "insufficient"
        if self.resolved < 5:
            return "preliminary"
        return "adequate"


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
    if jsonl_path.is_file():
        return _load_jsonl(jsonl_path)
    if json_fallback.is_file():
        return _load_json_array(json_fallback)
    return []


# ---------------------------------------------------------------------------
# Normalization
# ---------------------------------------------------------------------------


def normalize_outcome(raw: str) -> str:
    return normalize_outcome_value(raw)


def detect_platform(workspace: str, source: str) -> str:
    combined = f"{workspace} {source}"
    for pat, label in _PLATFORM_PATTERNS:
        if pat.search(combined):
            return label
    ws_low = workspace.lower()
    for ws_key, plat in _WORKSPACE_PLATFORM.items():
        if ws_key in ws_low:
            return plat
    return "Unknown"


def title_to_patterns(title: str) -> list[str]:
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


def build_finding_rows(raw_rows: list[dict[str, Any]]) -> list[FindingRow]:
    rows: list[FindingRow] = []
    for r in raw_rows:
        semantics = derive_outcome_semantics(r)
        workspace = str(r.get("workspace") or r.get("engagement") or "")
        source = str(r.get("source") or "")
        platform = detect_platform(workspace, source)
        title = str(r.get("title") or "")
        rows.append(FindingRow(
            platform=platform,
            workspace=workspace,
            finding_id=str(r.get("finding_id") or r.get("submission_id") or ""),
            title=title,
            severity=str(r.get("severity") or r.get("severity_claimed") or "Unknown"),
            outcome=semantics.outcome,
            status=str(r.get("status") or ""),
            date=str(r.get("date") or r.get("submitted_date") or ""),
            learning_scope=semantics.learning_scope,
            patterns=title_to_patterns(title),
        ))
    return rows


def compute_platform_stats(
    finding_rows: list[FindingRow], now_str: str
) -> dict[str, PlatformStats]:
    platform_map: dict[str, PlatformStats] = {}
    # Per-platform × per-pattern accumulation
    pattern_acc: dict[tuple[str, str], PatternPrecision] = {}

    for row in finding_rows:
        plat = row.platform
        if plat not in platform_map:
            platform_map[plat] = PlatformStats(platform=plat, last_validated_at=now_str)
        ps = platform_map[plat]
        ps.total += 1

        if row.outcome == "accepted":
            ps.accepted += 1
        elif row.outcome == "rejected":
            ps.rejected += 1
        elif row.outcome == "duplicate":
            ps.duplicate += 1
        elif row.outcome == "in_review":
            ps.in_review += 1
        elif row.outcome == "withdrawn":
            ps.withdrawn += 1
        elif row.outcome in ("pending",):
            ps.pending += 1
        else:
            ps.unknown_outcome += 1

        # Per-pattern accumulation
        if row.learning_scope != "full":
            continue

        for pattern_id in row.patterns:
            key = (plat, pattern_id)
            if key not in pattern_acc:
                pattern_acc[key] = PatternPrecision(
                    pattern_id=pattern_id, platform=plat
                )
            pp = pattern_acc[key]
            pp.sample_size += 1
            if row.date and (not pp.last_seen or row.date > pp.last_seen):
                pp.last_seen = row.date
            if row.outcome == "accepted":
                pp.accepted += 1
            elif row.outcome == "rejected":
                pp.rejected += 1
            else:
                pp.unknown += 1

    # Attach pattern rows to their platform stats
    for (plat, _), pp in pattern_acc.items():
        if plat in platform_map:
            platform_map[plat].pattern_rows.append(pp)

    # Sort pattern rows by accepted desc
    for ps in platform_map.values():
        ps.pattern_rows.sort(key=lambda p: (-p.accepted, p.pattern_id))

    return platform_map


# ---------------------------------------------------------------------------
# Markdown rendering
# ---------------------------------------------------------------------------


def _pct(value: Optional[float]) -> str:
    if value is None:
        return "n/a"
    return f"{value * 100:.1f}%"


def _render_platform_md(ps: PlatformStats, now_str: str) -> str:
    lines = [
        f"# Per-Platform Precision: {ps.platform}",
        "",
        f"_Generated: {now_str}_",
        f"_sample_size: {ps.total} | last_validated_at: {now_str[:10]} | confidence: {ps.confidence()}_",
        "",
    ]

    if ps.total == 0:
        lines += [
            "## No Data",
            "",
            "No findings attributed to this platform in the current outcome ledger.",
        ]
        return "\n".join(lines) + "\n"

    prec = ps.precision()
    lines += [
        "## Summary",
        "",
        f"| Metric | Value |",
        f"|---|---:|",
        f"| Total findings | {ps.total} |",
        f"| Accepted | {ps.accepted} |",
        f"| Rejected | {ps.rejected} |",
        f"| Duplicate | {ps.duplicate} |",
        f"| In Review | {ps.in_review} |",
        f"| Pending | {ps.pending} |",
        f"| Withdrawn | {ps.withdrawn} |",
        f"| Unknown outcome | {ps.unknown_outcome} |",
        f"| **Resolved (acc+rej)** | **{ps.resolved}** |",
        f"| **Precision (acc/resolved)** | **{_pct(prec)}** |",
        f"| Confidence | {ps.confidence()} |",
        "",
    ]

    if ps.resolved < MIN_RESOLVED_FOR_PRECISION:
        lines += [
            f"> **INSUFFICIENT DATA** — need {MIN_RESOLVED_FOR_PRECISION} resolved outcomes for precision.",
            f"> Currently {ps.resolved} resolved. Results below are illustrative only.",
            "",
        ]

    if ps.pattern_rows:
        lines += [
            "## Per-Pattern Breakdown",
            "",
            "| Pattern | Accepted | Rejected | Unknown | Sample Size | Precision | Confidence |",
            "|---|---:|---:|---:|---:|---|---|",
        ]
        for pp in ps.pattern_rows:
            lines.append(
                f"| `{pp.pattern_id}` | {pp.accepted} | {pp.rejected} "
                f"| {pp.unknown} | {pp.sample_size} "
                f"| {_pct(pp.precision())} | {pp.confidence()} |"
            )
    else:
        lines += [
            "## Per-Pattern Breakdown",
            "",
            "No patterns linked from finding titles for this platform.",
        ]

    return "\n".join(lines) + "\n"


def render_combined_md(
    platform_stats: dict[str, PlatformStats],
    finding_rows: list[FindingRow],
    now_str: str,
    date_str: str,
) -> str:
    total = len(finding_rows)
    outcome_counts = Counter(r.outcome for r in finding_rows)
    resolved = outcome_counts.get("accepted", 0) + outcome_counts.get("rejected", 0)
    overall_prec = (
        outcome_counts["accepted"] / resolved if resolved >= MIN_RESOLVED_FOR_PRECISION else None
    )

    lines = [
        f"# Per-Platform Precision Report — {date_str}",
        "",
        f"_Generated: {now_str}_",
        "",
        "## Overall Summary",
        "",
        f"| Metric | Value |",
        f"|---|---:|",
        f"| Total findings | {total} |",
        f"| Resolved (acc+rej) | {resolved} |",
        f"| Overall precision | {_pct(overall_prec)} |",
        "",
        "## Per-Platform Table",
        "",
        "| Platform | Total | Accepted | Rejected | Duplicate | In Review | Pending | Precision | Confidence |",
        "|---|---:|---:|---:|---:|---:|---:|---|---|",
    ]

    # Sort by total desc
    for plat in sorted(platform_stats, key=lambda p: -platform_stats[p].total):
        ps = platform_stats[plat]
        lines.append(
            f"| {plat} | {ps.total} | {ps.accepted} | {ps.rejected} "
            f"| {ps.duplicate} | {ps.in_review} | {ps.pending} "
            f"| {_pct(ps.precision())} | {ps.confidence()} |"
        )

    lines += ["", "## Honest Gaps", ""]
    if resolved < MIN_RESOLVED_FOR_PRECISION:
        lines += [
            f"- **INSUFFICIENT DATA**: only {resolved} resolved outcomes total (need {MIN_RESOLVED_FOR_PRECISION}+).",
            "- Precision figures are not computable. This section will populate once F1 Solodit ingest",
            "  or live engagement accepted/rejected outcomes are logged at scale.",
        ]
    else:
        lines += [
            "- Pattern linkage is heuristic (title keyword matching). Accuracy improves with structured metadata.",
            "- Platforms with 0 resolved outcomes have `n/a` precision.",
            "- Per-platform breakdowns are in `obsidian-vault/calibration/per-platform/<platform>.md`.",
        ]

    return "\n".join(lines) + "\n"


# ---------------------------------------------------------------------------
# Writers
# ---------------------------------------------------------------------------


def write_per_platform_vault(
    platform_stats: dict[str, PlatformStats], vault_dir: Path, now_str: str
) -> dict[str, Path]:
    out_dir = vault_dir / "calibration" / "per-platform"
    out_dir.mkdir(parents=True, exist_ok=True)
    written: dict[str, Path] = {}
    for plat, ps in platform_stats.items():
        safe_name = re.sub(r"[^a-zA-Z0-9\-]", "_", plat)
        out_path = out_dir / f"{safe_name}.md"
        out_path.write_text(_render_platform_md(ps, now_str), encoding="utf-8")
        written[plat] = out_path
    return written


def write_combined_md(
    platform_stats: dict[str, PlatformStats],
    finding_rows: list[FindingRow],
    docs_dir: Path,
    now_str: str,
    date_str: str,
) -> Path:
    out_path = docs_dir / f"PER_PLATFORM_PRECISION_{date_str}.md"
    docs_dir.mkdir(parents=True, exist_ok=True)
    out_path.write_text(
        render_combined_md(platform_stats, finding_rows, now_str, date_str),
        encoding="utf-8",
    )
    return out_path


def build_json_payload(
    platform_stats: dict[str, PlatformStats],
    finding_rows: list[FindingRow],
    now_str: str,
) -> dict[str, Any]:
    outcome_counts = Counter(r.outcome for r in finding_rows)
    resolved = outcome_counts.get("accepted", 0) + outcome_counts.get("rejected", 0)
    return {
        "schema": "auditooor.per_platform_precision.v1",
        "generated_at": now_str,
        "sample_size_discipline": {
            "min_resolved_for_precision": MIN_RESOLVED_FOR_PRECISION,
            "note": "n<3 resolved → precision=null; n<5 → confidence='preliminary'",
        },
        "overall": {
            "total_findings": len(finding_rows),
            "resolved": resolved,
            "accepted": outcome_counts.get("accepted", 0),
            "rejected": outcome_counts.get("rejected", 0),
            "outcome_distribution": dict(outcome_counts),
            "precision": (
                outcome_counts["accepted"] / resolved
                if resolved >= MIN_RESOLVED_FOR_PRECISION
                else None
            ),
        },
        "platforms": {
            plat: {
                "total": ps.total,
                "accepted": ps.accepted,
                "rejected": ps.rejected,
                "duplicate": ps.duplicate,
                "in_review": ps.in_review,
                "pending": ps.pending,
                "withdrawn": ps.withdrawn,
                "unknown_outcome": ps.unknown_outcome,
                "resolved": ps.resolved,
                "precision": ps.precision(),
                "confidence": ps.confidence(),
                "last_validated_at": ps.last_validated_at,
                "pattern_rows": [
                    {
                        "pattern_id": pp.pattern_id,
                        "accepted": pp.accepted,
                        "rejected": pp.rejected,
                        "unknown": pp.unknown,
                        "sample_size": pp.sample_size,
                        "precision": pp.precision(),
                        "confidence": pp.confidence(),
                        "last_seen": pp.last_seen,
                    }
                    for pp in ps.pattern_rows
                ],
            }
            for plat, ps in sorted(platform_stats.items(), key=lambda x: -x[1].total)
        },
    }


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------


def parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--outcomes",
        type=Path,
        default=DEFAULT_OUTCOMES_JSONL,
    )
    parser.add_argument("--vault-dir", type=Path, default=DEFAULT_VAULT)
    parser.add_argument("--docs-dir", type=Path, default=DEFAULT_DOCS_DIR)
    parser.add_argument("--out-json", type=Path, default=None)
    parser.add_argument("--print-json", action="store_true")
    parser.add_argument(
        "--dry-run",
        action="store_true",
        help="Skip file writes; print summary only.",
    )
    return parser.parse_args(argv)


def main(argv: list[str] | None = None) -> int:
    args = parse_args(argv)
    now = datetime.now(timezone.utc)
    now_str = now.strftime("%Y-%m-%dT%H:%M:%SZ")
    date_str = now.strftime("%Y-%m-%d")

    raw_rows = load_outcomes(args.outcomes, DEFAULT_OUTCOMES_JSON)
    print(f"[per-platform-precision] loaded {len(raw_rows)} rows", file=sys.stderr)

    finding_rows = build_finding_rows(raw_rows)
    platform_stats = compute_platform_stats(finding_rows, now_str)

    payload = build_json_payload(platform_stats, finding_rows, now_str)

    if not args.dry_run:
        # Write per-platform vault pages
        vault_paths = write_per_platform_vault(platform_stats, args.vault_dir, now_str)
        for plat, path in sorted(vault_paths.items()):
            print(f"[per-platform-precision] vault: {path}", file=sys.stderr)

        # Write combined doc
        doc_path = write_combined_md(platform_stats, finding_rows, args.docs_dir, now_str, date_str)
        print(f"[per-platform-precision] combined doc: {doc_path}", file=sys.stderr)

        # Write JSON
        if args.out_json:
            args.out_json.parent.mkdir(parents=True, exist_ok=True)
            args.out_json.write_text(
                json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8"
            )
            print(f"[per-platform-precision] JSON: {args.out_json}", file=sys.stderr)
    else:
        print("[per-platform-precision] --dry-run: no files written", file=sys.stderr)

    # Summary
    print("[per-platform-precision] platform row counts:", file=sys.stderr)
    for plat, ps in sorted(platform_stats.items(), key=lambda x: -x[1].total):
        print(
            f"  {plat:<15} total={ps.total:>4}  resolved={ps.resolved:>3}"
            f"  precision={_pct(ps.precision()):<8}  confidence={ps.confidence()}",
            file=sys.stderr,
        )

    if args.print_json:
        print(json.dumps(payload, indent=2, sort_keys=True))

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
