#!/usr/bin/env python3
"""
mcp-callable-usage-audit.py — Track E-4 (Wave-4 Big-Plan)

Audits usage frequency of every vault_<callable> across key doc/config files
and emits a promote/deprecate proposal table.

Classification tiers:
  heavy    >= 5 hits  : keep; document as Layer-1
  moderate  2-4 hits  : keep; document as Layer-2
  light     1 hit     : promote or deprecate (per below heuristics)
  silent    0 hits    : promote with strong recommendation or deprecate

Recommendation tags (per callable):
  PROMOTE_LAYER_1         : should be in canonical Layer-1 sequence
  PROMOTE_LAYER_2_SPECIFIC: useful in specific lane briefs; not Layer-1
  DEPRECATE               : low value vs maintenance cost
  KEEP_ADVISORY           : shipped; only useful for ad-hoc operator queries

Usage:
  python3 tools/mcp-callable-usage-audit.py [--out audit/mcp_callable_usage_2026-05-11.md] [--json]
"""
from __future__ import annotations

import argparse
import json
import os
import re
import sys
from pathlib import Path
from typing import Any

REPO_ROOT = Path(__file__).resolve().parents[1]
MCP_SERVER = REPO_ROOT / "tools" / "vault-mcp-server.py"

def _build_doc_paths() -> list[Path]:
    """Build corpus of doc/config files to search for callable citations."""
    paths: list[Path] = [
        Path.home() / ".claude" / "CLAUDE.md",
        REPO_ROOT / "CLAUDE.md",
        REPO_ROOT / "AGENTS.md",
        REPO_ROOT / "Makefile",
    ]
    docs_dir = REPO_ROOT / "docs"
    if docs_dir.exists():
        paths.extend(sorted(docs_dir.glob("*.md")))
    scheduled = Path.home() / ".claude" / "scheduled-tasks"
    if scheduled.exists():
        paths.extend(sorted(scheduled.glob("*/SKILL.md")))
    skills = Path.home() / ".claude" / "skills"
    if skills.exists():
        paths.extend(sorted(skills.glob("*/SKILL.md")))
    return paths


DOC_PATHS: list[Path] = _build_doc_paths()


# Per-callable recommendation map.
# Each entry: (tag, rationale)
# Built from analysis of actual invocation patterns + sub-report 04 §5.
_RECOMMENDATIONS: dict[str, tuple[str, str]] = {
    # --- Layer-1 core (recall context) ---
    "vault_resume_context": (
        "PROMOTE_LAYER_1",
        "canonical Layer-1 opener in every loop; already in CLAUDE.md §1b",
    ),
    "vault_exploit_context": (
        "PROMOTE_LAYER_1",
        "Layer-1 exploit-angle recall; cited in AGENTS.md + CLAUDE.md §1b",
    ),
    "vault_harness_context": (
        "PROMOTE_LAYER_1",
        "Layer-1 harness state; required before PoC build lane",
    ),
    "vault_knowledge_gap_context": (
        "PROMOTE_LAYER_1",
        "Layer-1 open-gap feed; drives loop dispatch priorities",
    ),
    "vault_engagement_status": (
        "PROMOTE_LAYER_1",
        "Layer-1 submission-lane state; required before filing or dropping",
    ),
    # --- Layer-2 specific lanes ---
    "vault_dispatch_context": (
        "PROMOTE_LAYER_2_SPECIFIC",
        "dispatch-preflight lane; call before spawning workers to confirm scope",
    ),
    "vault_finalization_context": (
        "PROMOTE_LAYER_2_SPECIFIC",
        "filing lane only; call when promoting draft to paste_ready",
    ),
    "vault_outcome_context": (
        "PROMOTE_LAYER_1",
        "retrospective feed for continuous-learning loop; should be Layer-1; "
        "triager outcomes are the loop's input signal",
    ),
    "vault_detector_provenance": (
        "PROMOTE_LAYER_2_SPECIFIC",
        "dispatch-preflight + pattern-authoring; call when a detector fires to trace callee + tests",
    ),
    "vault_finding_lineage": (
        "PROMOTE_LAYER_2_SPECIFIC",
        "filing lane; call before re-filing to check prior-loop exposure + M14-trap mentions",
    ),
    "vault_commit_mining_state": (
        "PROMOTE_LAYER_2_SPECIFIC",
        "Tier-6 mining lane; call at start of every commit-mining session",
    ),
    "vault_external_corpus_search": (
        "PROMOTE_LAYER_2_SPECIFIC",
        "originality defense lane; call before filing to surface corpus matches",
    ),
    "vault_llm_calibration": (
        "KEEP_ADVISORY",
        "ad-hoc budget/provider query; no auto-invocation pattern established",
    ),
    "vault_issue_session_token": (
        "KEEP_ADVISORY",
        "mutating-callable gate; invoked by wrappers; not a direct orchestrator call",
    ),
    "vault_verify_session_token": (
        "KEEP_ADVISORY",
        "token verification; called by mutating-callable wrappers internally",
    ),
    "vault_route": (
        "PROMOTE_LAYER_2_SPECIFIC",
        "routing helper; call when unsure which context callable to invoke first",
    ),
    "vault_harness_failure_context": (
        "PROMOTE_LAYER_2_SPECIFIC",
        "PoC debug lane; call when a harness test fails to get prior failure patterns",
    ),
    "vault_triager_pattern_context": (
        "PROMOTE_LAYER_2_SPECIFIC",
        "pre-filing lane; call to surface triager reject patterns before submitting",
    ),
    "vault_provider_capacity": (
        "KEEP_ADVISORY",
        "budget/capacity query; ad-hoc operator use; no auto-invocation established",
    ),
    "vault_spark_engagement_context": (
        "PROMOTE_LAYER_2_SPECIFIC",
        "Spark-specific lane; call in every Spark-hunt loop iteration as Layer-2",
    ),
    "vault_engage_report_context": (
        "PROMOTE_LAYER_2_SPECIFIC",
        "detector-output feed; call after engage.py stages 1-10 to load cluster summary",
    ),
    "vault_corpus_mining_state": (
        "PROMOTE_LAYER_2_SPECIFIC",
        "corpus-mining lane; call at start of W2 corpus-mining sessions",
    ),
    "vault_hacker_brief_for_lane": (
        "PROMOTE_LAYER_2_SPECIFIC",
        "per-lane dispatch brief; call before spawning a lane worker",
    ),
    "vault_lane_cooldown_check": (
        "PROMOTE_LAYER_2_SPECIFIC",
        "cooldown gate; call before re-dispatching a recently-attempted lane",
    ),
    "vault_kill_rubric_context": (
        "PROMOTE_LAYER_2_SPECIFIC",
        "kill-rubric enforcement; call when evaluating whether to drop a candidate",
    ),
    "vault_bug_family_heatmap": (
        "PROMOTE_LAYER_2_SPECIFIC",
        "cross-engagement pattern feed; call when starting a new engagement to prioritize families",
    ),
    "vault_language_patterns": (
        "PROMOTE_LAYER_2_SPECIFIC",
        "language-specific pattern slice; call when asset roster splits across Solidity/Go/Rust",
    ),
    "vault_dupe_rejection_context": (
        "PROMOTE_LAYER_2_SPECIFIC",
        "L31 dupe-preflight; call before filing to surface prior rejection + dupe flags",
    ),
    "vault_intent_resolve": (
        "PROMOTE_LAYER_2_SPECIFIC",
        "W2 intent-resolution layer; call when a query could match multiple callables",
    ),
    "vault_remember": (
        "KEEP_ADVISORY",
        "mutating write callable; operator-triggered; not for auto-invocation in loop",
    ),
    "vault_originality_context": (
        "PROMOTE_LAYER_2_SPECIFIC",
        "originality defense lane; call before filing to check prior-audit-pin originality",
    ),
    "vault_search": (
        "KEEP_ADVISORY",
        "raw vault search; ad-hoc operator use; prefer typed context callables in loops",
    ),
    "vault_get": (
        "KEEP_ADVISORY",
        "raw vault get-by-path; ad-hoc operator use; prefer typed context callables",
    ),
    "vault_next_loop": (
        "PROMOTE_LAYER_2_SPECIFIC",
        "loop-queue feed; call at end of each iteration to pull next priorities",
    ),
    "vault_goal_state": (
        "PROMOTE_LAYER_2_SPECIFIC",
        "goal state feed; call at session start to confirm current engagement goals",
    ),
}


def enumerate_callables(server_path: Path) -> list[str]:
    """Return sorted unique vault_<name> strings from TOOL_SCHEMAS in vault-mcp-server.py."""
    text = server_path.read_text(encoding="utf-8", errors="replace")
    names = sorted(set(re.findall(r'"name":\s*"(vault_\w+)"', text)))
    return names


def count_citations(callable_name: str, doc_paths: list[Path]) -> dict[str, int]:
    """Return per-doc citation count for callable_name."""
    counts: dict[str, int] = {}
    for path in doc_paths:
        if not path.exists():
            continue
        try:
            text = path.read_text(encoding="utf-8", errors="replace")
        except OSError:
            continue
        hits = len(re.findall(re.escape(callable_name), text))
        if hits:
            # Use a short label: relative-to-home or repo-relative or basename
            try:
                label = str(path.relative_to(Path.home()))
            except ValueError:
                try:
                    label = str(path.relative_to(REPO_ROOT))
                except ValueError:
                    label = path.name
            counts[label] = hits
    return counts


def classify(total: int) -> str:
    if total >= 5:
        return "heavy"
    if total >= 2:
        return "moderate"
    if total == 1:
        return "light"
    return "silent"


def recommend(callable_name: str, tier: str) -> tuple[str, str]:
    """Return (tag, rationale) from static map, or default based on tier."""
    if callable_name in _RECOMMENDATIONS:
        return _RECOMMENDATIONS[callable_name]
    # Fallback heuristics
    if tier in ("heavy", "moderate"):
        return ("KEEP_ADVISORY", "sufficient usage; keep as-is")
    if tier == "light":
        return ("PROMOTE_LAYER_2_SPECIFIC", "low usage; promote to a specific lane brief")
    return ("DEPRECATE", "zero usage; no auto-invocation pattern; consider removal")


def audit(server_path: Path, doc_paths: list[Path]) -> list[dict[str, Any]]:
    callables = enumerate_callables(server_path)
    rows: list[dict[str, Any]] = []
    for name in callables:
        per_doc = count_citations(name, doc_paths)
        total = sum(per_doc.values())
        tier = classify(total)
        tag, rationale = recommend(name, tier)
        rows.append({
            "callable": name,
            "total_citations": total,
            "per_doc": per_doc,
            "tier": tier,
            "recommendation": tag,
            "rationale": rationale,
        })
    # Sort: silent first (most action needed), then light, moderate, heavy; secondary: name
    tier_order = {"silent": 0, "light": 1, "moderate": 2, "heavy": 3}
    rows.sort(key=lambda r: (tier_order[r["tier"]], r["callable"]))
    return rows


def render_markdown(rows: list[dict[str, Any]], doc_paths: list[Path]) -> str:
    lines = [
        "# MCP Callable Usage Audit",
        "",
        f"Generated: 2026-05-11  |  Total callables: {len(rows)}  |  Corpus: {len(doc_paths)} doc/config files",
        "",
        "## Classification",
        "",
        "| Tier | Threshold |",
        "|------|-----------|",
        "| heavy | >= 5 citations |",
        "| moderate | 2-4 citations |",
        "| light | 1 citation |",
        "| silent | 0 citations |",
        "",
        "## Recommendations",
        "",
        "| Tag | Meaning |",
        "|-----|---------|",
        "| PROMOTE_LAYER_1 | Add to canonical Layer-1 sequence in CLAUDE.md §1b |",
        "| PROMOTE_LAYER_2_SPECIFIC | Add to a specific lane brief (dispatch/filing/mining/...) |",
        "| KEEP_ADVISORY | Shipped; only useful for ad-hoc operator queries; no auto-invocation |",
        "| DEPRECATE | Low value vs maintenance cost; remove in a future minor version |",
        "",
        "## Callable Table",
        "",
        "| Callable | Total Citations | Tier | Recommendation | Rationale |",
        "|----------|----------------|------|----------------|-----------|",
    ]
    for row in rows:
        lines.append(
            f"| `{row['callable']}` | {row['total_citations']} | {row['tier']} "
            f"| {row['recommendation']} | {row['rationale']} |"
        )

    # Summary by tier + recommendation
    from collections import Counter
    tier_counts = Counter(r["tier"] for r in rows)
    rec_counts = Counter(r["recommendation"] for r in rows)

    lines += [
        "",
        "## Summary",
        "",
        "### By tier",
        "",
    ]
    for tier in ("silent", "light", "moderate", "heavy"):
        lines.append(f"- {tier}: {tier_counts.get(tier, 0)}")

    lines += [
        "",
        "### By recommendation",
        "",
    ]
    for tag in ("PROMOTE_LAYER_1", "PROMOTE_LAYER_2_SPECIFIC", "KEEP_ADVISORY", "DEPRECATE"):
        lines.append(f"- {tag}: {rec_counts.get(tag, 0)}")

    lines += [
        "",
        "## Per-callable citation detail",
        "",
    ]
    for row in rows:
        if row["per_doc"]:
            lines.append(f"### `{row['callable']}`")
            for doc, count in sorted(row["per_doc"].items(), key=lambda kv: -kv[1]):
                lines.append(f"- {doc}: {count}")
            lines.append("")

    return "\n".join(lines)


def main() -> None:
    p = argparse.ArgumentParser(
        description="Audit MCP callable usage frequency and emit promote/deprecate proposals."
    )
    p.add_argument(
        "--out", default=None,
        help="Write markdown report to this path (default: print to stdout)"
    )
    p.add_argument(
        "--json", action="store_true", dest="as_json",
        help="Emit JSON array instead of markdown"
    )
    args = p.parse_args()

    if not MCP_SERVER.exists():
        print(f"ERROR: vault-mcp-server.py not found at {MCP_SERVER}", file=sys.stderr)
        sys.exit(1)

    # Resolve doc paths (filter to existing)
    doc_paths = list(DOC_PATHS)

    rows = audit(MCP_SERVER, doc_paths)

    if args.as_json:
        output = json.dumps(rows, indent=2)
    else:
        output = render_markdown(rows, doc_paths)

    if args.out:
        out_path = Path(args.out)
        out_path.parent.mkdir(parents=True, exist_ok=True)
        out_path.write_text(output, encoding="utf-8")
        print(f"[mcp-callable-usage-audit] report written to {out_path}")
        # Also print summary to stdout
        from collections import Counter
        tier_counts = Counter(r["tier"] for r in rows)
        rec_counts = Counter(r["recommendation"] for r in rows)
        print(f"  callables: {len(rows)}")
        print(f"  tiers: heavy={tier_counts['heavy']} moderate={tier_counts['moderate']} "
              f"light={tier_counts['light']} silent={tier_counts['silent']}")
        for tag in ("PROMOTE_LAYER_1", "PROMOTE_LAYER_2_SPECIFIC", "KEEP_ADVISORY", "DEPRECATE"):
            print(f"  {tag}: {rec_counts.get(tag, 0)}")
    else:
        print(output)


if __name__ == "__main__":
    main()
