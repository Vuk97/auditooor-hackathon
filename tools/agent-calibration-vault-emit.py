#!/usr/bin/env python3
"""agent-calibration-vault-emit.py — Surface agent + provider performance into the Obsidian vault.

Reads calibration logs and routing docs (read-only) and emits structured
Markdown notes into obsidian-vault/calibration/ with Dataview-compatible
YAML frontmatter.

Output layout:
  obsidian-vault/calibration/
    INDEX.md
    providers/<provider>.md
    task-types/<task-type>.md
    incidents/<id>.md
    routing-decisions/<date>.md

Usage:
  python3 tools/agent-calibration-vault-emit.py [--vault-dir obsidian-vault]
  python3 tools/agent-calibration-vault-emit.py --dry-run
  python3 tools/agent-calibration-vault-emit.py --section providers

Sources (all read-only):
  tools/calibration/llm_calibration_log.jsonl
  tools/calibration/llm_budget_log.jsonl
  tools/calibration/llm_budget.json
  tools/calibration/routing_manifest.yaml

Constraints:
  - NEVER mutates source files
  - No LLM calls; pure data aggregation
  - Surfaces "no data" when a provider/task-type combo has zero logs
  - Marks n<5 recommendations as "preliminary guidance only"
"""
from __future__ import annotations

import argparse
import datetime as _dt
import json
import os
import re
import sys
from collections import defaultdict
from pathlib import Path
from typing import Any

try:
    import yaml as _yaml
    HAS_YAML = True
except ImportError:
    HAS_YAML = False

REPO_ROOT = Path(__file__).resolve().parent.parent
CAL_LOG = REPO_ROOT / "tools" / "calibration" / "llm_calibration_log.jsonl"
BUDGET_LOG = REPO_ROOT / "tools" / "calibration" / "llm_budget_log.jsonl"
ROUTING_MANIFEST = REPO_ROOT / "tools" / "calibration" / "routing_manifest.yaml"


def load_jsonl(path: Path) -> list:
    if not path.exists():
        return []
    rows = []
    with open(path, encoding="utf-8") as fh:
        for line in fh:
            line = line.strip()
            if line:
                try:
                    rows.append(json.loads(line))
                except json.JSONDecodeError:
                    pass
    return rows


def load_routing_manifest() -> dict:
    if not ROUTING_MANIFEST.exists() or not HAS_YAML:
        return {}
    with open(ROUTING_MANIFEST, encoding="utf-8") as fh:
        return _yaml.safe_load(fh) or {}


def display_path(path: Path) -> str:
    resolved = path.resolve()
    try:
        return str(resolved.relative_to(REPO_ROOT))
    except ValueError:
        return str(resolved)


def compute_provider_stats(cal_entries, budget_entries):
    by_provider = defaultdict(lambda: {
        "total": 0, "true": 0, "false": 0, "skipped": 0,
        "task_types": defaultdict(lambda: {"total": 0, "true": 0, "false": 0, "skipped": 0})
    })
    for e in cal_entries:
        p = e.get("provider", "unknown")
        t = e.get("task_type", "unknown")
        v = e.get("verdict", "")
        by_provider[p]["total"] += 1
        by_provider[p]["task_types"][t]["total"] += 1
        if v == "TRUE":
            by_provider[p]["true"] += 1
            by_provider[p]["task_types"][t]["true"] += 1
        elif v == "FALSE":
            by_provider[p]["false"] += 1
            by_provider[p]["task_types"][t]["false"] += 1
        else:
            by_provider[p]["skipped"] += 1
            by_provider[p]["task_types"][t]["skipped"] += 1

    by_prov_budget = defaultdict(lambda: {"calls": 0, "total_tokens": 0, "success": 0})
    for e in budget_entries:
        p = e.get("provider", "unknown")
        by_prov_budget[p]["calls"] += 1
        by_prov_budget[p]["total_tokens"] += e.get("tokens_used", 0)
        if e.get("success"):
            by_prov_budget[p]["success"] += 1

    result = {}
    for p in set(by_provider.keys()) | set(by_prov_budget.keys()):
        cal = by_provider.get(p, {"total": 0, "true": 0, "false": 0, "skipped": 0, "task_types": {}})
        bud = by_prov_budget.get(p, {"calls": 0, "total_tokens": 0, "success": 0})
        decided = cal["true"] + cal["false"]
        tp_rate = cal["true"] / decided if decided > 0 else None
        avg_tokens = bud["total_tokens"] / bud["calls"] if bud["calls"] > 0 else 0
        result[p] = {
            "total_calibration_dispatches": cal["total"],
            "decided": decided,
            "true": cal["true"],
            "false": cal["false"],
            "skipped": cal["skipped"],
            "tp_rate": tp_rate,
            "budget_calls": bud["calls"],
            "total_tokens": bud["total_tokens"],
            "avg_tokens_per_call": avg_tokens,
            "budget_success_rate": bud["success"] / bud["calls"] if bud["calls"] > 0 else None,
            "task_type_stats": dict(cal.get("task_types", {})),
        }
    return result


def compute_task_type_stats(cal_entries):
    by_task = defaultdict(lambda: {
        "total": 0, "decided": 0, "true": 0, "false": 0,
        "providers": defaultdict(lambda: {"total": 0, "true": 0, "false": 0})
    })
    for e in cal_entries:
        p = e.get("provider", "unknown")
        t = e.get("task_type", "unknown")
        v = e.get("verdict", "")
        by_task[t]["total"] += 1
        by_task[t]["providers"][p]["total"] += 1
        if v == "TRUE":
            by_task[t]["true"] += 1
            by_task[t]["decided"] += 1
            by_task[t]["providers"][p]["true"] += 1
        elif v == "FALSE":
            by_task[t]["false"] += 1
            by_task[t]["decided"] += 1
            by_task[t]["providers"][p]["false"] += 1
    return {t: {**s, "providers": dict(s["providers"])} for t, s in by_task.items()}


def fm(**kwargs):
    lines = ["---"]
    for k, v in kwargs.items():
        if v is None:
            v = ""
        elif isinstance(v, list):
            v = "[" + ", ".join(f'"{x}"' for x in v) + "]"
        elif isinstance(v, bool):
            v = str(v).lower()
        else:
            v = f'"{v}"'
        lines.append(f"{k}: {v}")
    lines.append("---")
    return "\n".join(lines)


def now_utc():
    return _dt.datetime.now(_dt.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


KNOWN_INCIDENTS = [
    {
        "id": "INC-001-fp-repair-v2-regex-trick",
        "date": "2026-05-04",
        "severity": "High",
        "providers_involved": ["minimax"],
        "task_type": "fp-repair-yaml",
        "pr_refs": ["PR #607", "PR #608", "PR #609", "PR #614"],
        "status": "mitigated",
        "summary": (
            "fp_repair_v2 wire pass dispatched 386 LLM tasks. "
            "All 91 newly-emitted YAMLs (100%) regressed to the same fixture-shape predicate: "
            "`function.body_not_contains_regex: \"require\\\\s*\\\\(\"`. "
            "These are not bug-class detectors - they fire on every function lacking require() "
            "regardless of actual vulnerability."
        ),
        "root_cause": (
            "The prompt asked to 'distinguish the two fixtures' and 'make the predicate stricter'. "
            "Fixtures had uniform shape (vuln=no-require, clean=has-require) from upstream "
            "Phase-B-prime synthesis. LLM correctly executed the (wrong) prompt instruction."
        ),
        "impact": (
            "91 fake detectors queued for bulk-promote. All smoke-passed. "
            "Zero real production bugs would have been caught. "
            "162 additional in-production fakes sharing the same trick signature surfaced."
        ),
        "mitigation": (
            "Layer A: agent-dispatch-prompt-lint.py - catches fixture-shape phrasings before dispatch. "
            "Layer C: predicate-semantic-lint.py - refuses scope-only + bare-regex predicates. "
            "Layer D: wirer-output-diversity-check.py - catches cohort regression. "
            "Guarded chain: wire-and-promote-with-guards.sh mandates all three before promote."
        ),
        "lessons_learned": (
            "1. M14-trap applies to YOUR OWN tooling: the harness believed 162 fakes were real. "
            "2. Prompt design is cheapest defense but leaky - Layer A reduces probability, not eliminates. "
            "3. Smoke-pass is necessary but not sufficient. "
            "4. Defense in depth: no single layer catches all failure modes."
        ),
    },
    {
        "id": "INC-002-kimi-gap-finding-freefall",
        "date": "2026-04-25",
        "severity": "Medium",
        "providers_involved": ["kimi"],
        "task_type": "gap-finding",
        "pr_refs": ["EMPIRICAL_ROUTING_2026-05-04"],
        "status": "active-watch",
        "summary": (
            "Kimi gap-finding TP rate measured at 20% (1T/4F, n=6). "
            "Below the 70% routing floor. Kimi PR-review runs at 93% for the same session; "
            "gap-finding is specifically weak."
        ),
        "root_cause": (
            "Gap-finding requires novel hypothesis generation - a task where over-claiming is easy. "
            "Kimi tends to generate plausible-sounding gaps that local grep contradicts."
        ),
        "impact": (
            "Any gap-finding dispatch to kimi produces ~4x more false flags than real gaps. "
            "Operator time wasted verifying non-gaps."
        ),
        "mitigation": (
            "Demoted to advisory-only for gap-finding. "
            "Mandatory local grep pre-check before any kimi gap-finding flag is acted on."
        ),
        "lessons_learned": (
            "1. Provider strength on one task (93% PR-review) does not transfer to structurally "
            "different tasks (20% gap-finding). "
            "2. Gap-finding needs n>=20 per provider before routing floor can be assessed."
        ),
    },
    {
        "id": "INC-003-minimax-gap-finding-weak",
        "date": "2026-04-25",
        "severity": "Medium",
        "providers_involved": ["minimax"],
        "task_type": "gap-finding",
        "pr_refs": ["EMPIRICAL_ROUTING_2026-05-04"],
        "status": "active-watch",
        "summary": (
            "Minimax gap-finding TP rate measured at 33% (2T/4F, n=6). "
            "Below the 70% routing floor. Minimax adversarial-kill runs at 100% for the same session."
        ),
        "root_cause": (
            "Same structural problem as kimi gap-finding: novel-hypothesis generation "
            "is over-claiming territory."
        ),
        "impact": (
            "Any gap-finding dispatch to minimax produces ~2x more false flags than real gaps."
        ),
        "mitigation": (
            "Advisory-only for gap-finding. Same local-grep pre-check requirement as kimi."
        ),
        "lessons_learned": (
            "1. Neither primary provider meets the 70% routing floor for gap-finding. "
            "2. May require a different prompt paradigm (checklist-based rather than open-ended). "
            "3. Collect 20+ samples per provider before re-evaluating floor."
        ),
    },
    {
        "id": "INC-004-provider-impact-analysis-underfed-packets",
        "date": "2026-05-17",
        "severity": "Medium",
        "providers_involved": ["kimi", "minimax"],
        "task_type": "impact_analysis",
        "pr_refs": ["commit 520606e316"],
        "status": "mitigated",
        "summary": (
            "Provider-assist review during capability-roadmap slice 8 showed that "
            "Minimax can produce useful bounded adversarial review when the packet "
            "contains exact file/diff context, but thin packets mostly return "
            "INDETERMINATE. Kimi handled nuanced code-review and compatibility "
            "inventory better, but several long/sparse packets timed out or returned "
            "no output."
        ),
        "root_cause": (
            "The task type was routed through generic impact_analysis prompts without "
            "a standardized packet schema. Some packets asked for concrete review while "
            "omitting the actual code/diff or enough artifact context."
        ),
        "impact": (
            "Token burn was partially wasted on INDETERMINATE/no-output results. "
            "Useful provider suggestions still landed after local verification: "
            "missing-recipient fixture hardening, pre-source-read legacy target/docs, "
            "external recall quality tests, and chain-candidates cache design notes."
        ),
        "mitigation": (
            "Keep impact_analysis advisory-only. Require self-contained packets with "
            "exact snippets/diffs, explicit truncation flag, expected output shape, "
            "and local verification before any suggestion enters the tree. Prefer "
            "Kimi for nuanced compatibility/code review; use Minimax for bounded "
            "adversarial review only when the packet is complete."
        ),
        "lessons_learned": (
            "1. Minimax is not useless; it is brittle to missing context. "
            "2. Kimi is the better default for ambiguous code-review reasoning. "
            "3. Provider token-saving only works when packet construction is treated "
            "as engineering work, not chat prompting."
        ),
    },
]

ROUTING_DECISIONS_2026_05_04 = [
    {
        "title": "Demote gap-finding for kimi and minimax to advisory-only",
        "date": "2026-05-04",
        "task_type": "gap-finding",
        "provider_from": "kimi + minimax (primary)",
        "provider_to": "advisory-only",
        "reason": "TP rates of 20% (kimi) and 33% (minimax) are below the 70% routing floor.",
        "evidence": "EMPIRICAL_ROUTING_2026-05-04.md negative routing findings",
        "pr_ref": "N/A (policy decision)",
    },
    {
        "title": "Promote kimi/source-extraction to primary routing",
        "date": "2026-05-04",
        "task_type": "source-extraction",
        "provider_from": "advisory",
        "provider_to": "kimi (primary-allowed-by-seed)",
        "reason": "100% TP rate on n=23 decided rows. Meets both sample-size and accuracy floors.",
        "evidence": "EMPIRICAL_ROUTING_2026-05-04.md rank 2",
        "pr_ref": "N/A (policy decision)",
    },
    {
        "title": "Promote minimax/adversarial-kill to primary routing",
        "date": "2026-05-04",
        "task_type": "adversarial-kill",
        "provider_from": "advisory",
        "provider_to": "minimax (primary-allowed-by-seed)",
        "reason": "100% TP rate on n=23 decided rows. Meets all floors.",
        "evidence": "EMPIRICAL_ROUTING_2026-05-04.md rank 3",
        "pr_ref": "N/A (policy decision)",
    },
    {
        "title": "Apply guarded chain mandatory for all fixture-synthesis + fp-repair dispatches",
        "date": "2026-05-04",
        "task_type": "fixture-synthesis + fp-repair-yaml",
        "provider_from": "unguarded minimax dispatch",
        "provider_to": "minimax via guarded chain (prompt-lint + diversity + semantic-lint)",
        "reason": "INC-001: 91/91 fakes all smoke-passed without the guarded chain.",
        "evidence": "INC-001-fp-repair-v2-regex-trick",
        "pr_ref": "PR #607, #608, #609, #614",
    },
    {
        "title": "Flag kimi/pr-review and minimax/pr-review for seed-row promotion",
        "date": "2026-05-04",
        "task_type": "pr-review",
        "provider_from": "empirically qualified, no seed row",
        "provider_to": "primary routing pending seed-row creation",
        "reason": "kimi 93% TP (n=27), minimax 83% TP (n=18). Both qualify empirically.",
        "evidence": "EMPIRICAL_ROUTING_2026-05-04.md rank 1 and 4",
        "pr_ref": "N/A (policy decision)",
    },
]

ROUTING_DECISIONS_2026_05_17 = [
    {
        "title": "Add impact_analysis as advisory-only provider lane",
        "date": "2026-05-17",
        "task_type": "impact_analysis",
        "provider_from": "untyped provider-assist prompts",
        "provider_to": "kimi preferred / minimax fallback, advisory-only",
        "reason": "Slice 8 provider outputs were useful only after local verification; thin packets caused Minimax INDETERMINATE results and Kimi timeout/no-output rows.",
        "evidence": "reports/capability_roadmap_slice8_closeout_2026-05-17.md",
        "pr_ref": "commit 520606e316",
    },
    {
        "title": "Require self-contained Minimax packets",
        "date": "2026-05-17",
        "task_type": "impact_analysis",
        "provider_from": "thin adversarial prompts",
        "provider_to": "self-contained packet with exact file/diff excerpts",
        "reason": "Minimax returned useful reviews for packets with concrete content and INDETERMINATE for underfed prompts.",
        "evidence": ".auditooor/dispatch_outputs/{54371902,70f7da4d,f803fad7,4eafffc7}-impact_analysis.txt versus {c3b3ad97,48ce823d,551d7b14}-impact_analysis.txt",
        "pr_ref": "commit 520606e316",
    },
]


def _fmt_mitigation(m) -> str:
    """A mitigation row is usually a plain string, but the routing manifest also
    carries single-key {label: detail} dicts (e.g. {"See INC-001": "..."}); render
    a dict as "label: detail" so ', '.join over a mixed list never raises TypeError."""
    if isinstance(m, dict):
        return "; ".join(f"{k}: {v}" for k, v in m.items())
    return str(m)


def emit_index(provider_stats, task_type_stats, incident_ids, routing_dates):
    providers = sorted(p for p in provider_stats if p not in ("unknown",))
    task_types = sorted(t for t in task_type_stats if t != "unknown")
    total_dispatches = sum(v["total_calibration_dispatches"] for v in provider_stats.values())
    total_budget_calls = sum(v["budget_calls"] for v in provider_stats.values())
    total_tokens = sum(v["total_tokens"] for v in provider_stats.values())

    lines = [
        fm(
            category="calibration-index",
            generated_at=now_utc(),
            total_dispatches=total_dispatches,
            total_budget_calls=total_budget_calls,
            total_tokens=total_tokens,
            schema="auditooor.calibration.vault.v1",
        ),
        "", "# Agent + Provider Calibration - Index", "",
        "> Generated by `tools/agent-calibration-vault-emit.py`. Read-only source logs.",
        "> Re-run with `make agent-calibration-refresh` to update.", "",
        "## Quick-answer routing table", "",
        "| Task type | Best provider | TP rate | n | Status |",
        "|-----------|--------------|---------|---|--------|",
    ]

    for tt in task_types:
        ts = task_type_stats[tt]
        best_prov = None
        best_tp = -1
        best_n = 0
        for prov, ps in ts.get("providers", {}).items():
            if prov == "unknown":
                continue
            d = ps.get("true", 0) + ps.get("false", 0)
            if d > 0:
                tp = ps["true"] / d
                if tp > best_tp or (tp == best_tp and d > best_n):
                    best_tp = tp
                    best_prov = prov
                    best_n = d
        if best_prov is None:
            lines.append(f"| `{tt}` | - | no data | 0 | no-data |")
        else:
            status = "primary" if best_n >= 5 and best_tp >= 0.70 else "preliminary"
            lines.append(f"| `{tt}` | `{best_prov}` | {best_tp*100:.1f}% | {best_n} | {status} |")

    lines += ["", "## Provider notes", ""]
    for p in providers:
        ps = provider_stats[p]
        tp = f"{ps['tp_rate']*100:.1f}%" if ps["tp_rate"] is not None else "no-data"
        lines.append(f"- [[calibration/providers/{p}|{p}]] - {ps['total_calibration_dispatches']} dispatches, TP={tp}")

    lines += ["", "## Task-type notes", ""]
    for tt in task_types:
        ts = task_type_stats[tt]
        d = ts.get("decided", 0)
        tp_str = f"{ts['true']/d*100:.1f}%" if d > 0 else "no-data"
        lines.append(f"- [[calibration/task-types/{tt}|{tt}]] - n={ts['total']}, decided={d}, overall TP={tp_str}")

    lines += ["", "## Incidents", ""]
    for inc in incident_ids:
        lines.append(f"- [[calibration/incidents/{inc}|{inc}]]")

    lines += ["", "## Routing decisions log", ""]
    for rd in routing_dates:
        lines.append(f"- [[calibration/routing-decisions/{rd}|{rd}]]")

    lines += [
        "", "## Dataview: best provider per task-type", "",
        "```dataview",
        "TABLE best_provider, overall_tp_rate, decided, status",
        'FROM "calibration/task-types"',
        "SORT overall_tp_rate DESC",
        "```",
        "", "## Dataview: provider summary", "",
        "```dataview",
        "TABLE total_dispatches, overall_tp_rate, budget_calls, avg_tokens_per_call",
        'FROM "calibration/providers"',
        "SORT total_dispatches DESC",
        "```",
    ]
    return "\n".join(lines)


def emit_provider_note(provider, stats, routing_manifest, incidents_for_provider):
    tp_r = stats["tp_rate"]
    tp_display = f"{tp_r*100:.1f}%" if tp_r is not None else "no-data"
    lines = [
        fm(
            category="calibration-provider",
            provider=provider,
            generated_at=now_utc(),
            total_dispatches=stats["total_calibration_dispatches"],
            decided=stats["decided"],
            overall_tp_rate=tp_display,
            budget_calls=stats["budget_calls"],
            total_tokens=stats["total_tokens"],
            avg_tokens_per_call=int(stats["avg_tokens_per_call"]),
        ),
        "", f"# Provider: `{provider}`", "", "## Overview", "",
        f"- **Total calibration dispatches**: {stats['total_calibration_dispatches']}",
        f"- **Decided** (TRUE+FALSE verdicts): {stats['decided']}",
        f"- **TRUE** (correct): {stats['true']}",
        f"- **FALSE** (incorrect/FP): {stats['false']}",
        f"- **Skipped** (no verdict): {stats['skipped']}",
        f"- **Overall TP rate**: {tp_display}",
        f"- **Budget calls**: {stats['budget_calls']:,}",
        f"- **Total tokens used**: {stats['total_tokens']:,}",
        f"- **Avg tokens/call**: {stats['avg_tokens_per_call']:.0f}",
    ]
    sr = stats.get("budget_success_rate")
    if sr is not None:
        lines.append(f"- **Budget success rate**: {sr*100:.1f}%")

    lines += [
        "", "## TP rate per task-type", "",
        "| Task type | n (decided) | TRUE | FALSE | TP rate | Status |",
        "|-----------|-------------|------|-------|---------|--------|",
    ]
    for tt, ts in sorted(stats.get("task_type_stats", {}).items()):
        d = ts.get("true", 0) + ts.get("false", 0)
        t = ts.get("true", 0)
        f_ = ts.get("false", 0)
        if d == 0:
            tp_str, status = "no data", "no-data"
        else:
            tp_val = t / d
            tp_str = f"{tp_val*100:.1f}%"
            status = "route-ok" if d >= 5 and tp_val >= 0.70 else ("do-not-route" if d >= 3 and tp_val < 0.50 else "preliminary")
        lines.append(f"| `{tt}` | {d} | {t} | {f_} | {tp_str} | {status} |")

    lines += ["", "## Routing recommendations", ""]
    manifest_tasks = routing_manifest.get("task_types", {})
    has_rec = False
    for tt, spec in manifest_tasks.items():
        if spec.get("preferred") == provider or spec.get("fallback") == provider:
            has_rec = True
            role = "preferred" if spec.get("preferred") == provider else "fallback"
            lines.append(f"- **`{tt}`** ({role}): thinking_weight=`{spec.get('thinking_weight','?')}`, budget_cap=`${spec.get('budget_per_task_usd','?')}`/task")
            if n := spec.get("notes"):
                lines.append(f"  - Notes: {n}")
    if not has_rec:
        lines.append("_No routing manifest entries for this provider yet._")

    lines += ["", "## M14-trap incidents", ""]
    if incidents_for_provider:
        for inc in incidents_for_provider:
            lines.append(f"- [[calibration/incidents/{inc['id']}|{inc['id']}]] - {inc['summary'][:80]}...")
    else:
        lines.append("_No recorded M14-trap incidents for this provider._")

    lines += [
        "", "## Honest limits", "",
        f"- Sample sizes: most task-types have n<30 for `{provider}`. Recommendations are heuristics.",
        "- No per-dispatch thinking_weight field in current logs.",
        "- Data is whatever is present in `tools/calibration/llm_calibration_log.jsonl` at emit time; rerun `make agent-calibration-refresh` after appending rows.",
        "", "---", "_[[calibration/INDEX|Back to Calibration Index]]_",
    ]
    return "\n".join(lines)


def emit_task_type_note(task_type, stats, routing_manifest):
    d = stats.get("decided", 0)
    tp_display = f"{stats['true']/d*100:.1f}%" if d > 0 else "no-data"
    prov_rows = stats.get("providers", {})
    best_prov = None
    best_tp = -1
    best_n = 0
    for p, ps in prov_rows.items():
        if p == "unknown":
            continue
        pn = ps.get("true", 0) + ps.get("false", 0)
        if pn > 0:
            pt = ps["true"] / pn
            if pt > best_tp or (pt == best_tp and pn > best_n):
                best_tp = pt
                best_prov = p
                best_n = pn

    manifest_spec = routing_manifest.get("task_types", {}).get(task_type, {})

    lines = [
        fm(
            category="calibration-task-type",
            task_type=task_type,
            generated_at=now_utc(),
            total_dispatches=stats["total"],
            decided=d,
            overall_tp_rate=tp_display,
            best_provider=best_prov or "no-data",
            n=d,
        ),
        "", f"# Task type: `{task_type}`", "", "## Overview", "",
        f"- **Total dispatches**: {stats['total']}",
        f"- **Decided** (TRUE+FALSE): {d}",
        f"- **Overall TP rate**: {tp_display}",
        f"- **Best provider**: {best_prov or 'no data'}",
        "", "## Provider comparison", "",
        "| Provider | n (decided) | TRUE | FALSE | TP rate | Recommendation |",
        "|----------|-------------|------|-------|---------|----------------|",
    ]
    for p, ps in sorted(prov_rows.items()):
        if p == "unknown":
            continue
        pn = ps.get("true", 0) + ps.get("false", 0)
        pt = ps.get("true", 0)
        pf = ps.get("false", 0)
        if pn == 0:
            tp_str, rec = "no data", "no-data"
        else:
            tp_val = pt / pn
            tp_str = f"{tp_val*100:.1f}%"
            rec = "route-ok" if pn >= 5 and tp_val >= 0.70 else f"preliminary (n={pn})" if pn < 5 else "do-not-route"
        lines.append(f"| `{p}` | {pn} | {pt} | {pf} | {tp_str} | {rec} |")

    lines += ["", "## Routing manifest", ""]
    if manifest_spec:
        lines += [
            f"- **Preferred**: `{manifest_spec.get('preferred','?')}`",
            f"- **Fallback**: `{manifest_spec.get('fallback','?')}`",
            f"- **Thinking weight**: `{manifest_spec.get('thinking_weight','?')}`",
            f"- **Budget cap/task**: `${manifest_spec.get('budget_per_task_usd','?')}`",
            f"- **Status**: `{manifest_spec.get('status','?')}`",
        ]
        if mits := manifest_spec.get("mitigations"):
            lines.append(
                f"- **Mitigations**: {', '.join(_fmt_mitigation(m) for m in mits)}")
        if notes := manifest_spec.get("notes"):
            lines.append(f"- **Notes**: {notes}")
    else:
        lines.append("_No routing manifest entry. Add to `tools/calibration/routing_manifest.yaml`._")

    WATCH_OUTS = {
        "gap-finding": "Both kimi (20% TP) and minimax (33% TP) score poorly. Do NOT use as primary router. Advisory-only with mandatory local grep pre-check.",
        "impact_analysis": "Advisory-only. Kimi is stronger for nuanced code-review/compatibility packets. Minimax can help with bounded adversarial review only when exact file/diff context is embedded; underfed packets mostly return INDETERMINATE.",
        "fixture-synthesis": "Risk of 100% regex-trick fake output (fp_repair_v2 incident). Use guarded chain: prompt-lint + diversity-check + semantic-lint.",
        "fp-repair-yaml": "FP-repair was the source of the 2026-05-04 incident (91/91 fakes). Apply guarded chain mandatory.",
        "pr-review": "Kimi 93% TP (n=27); minimax 83% (n=18). Strong but has produced FPs. Cross-check LLM claim against local grep before acting.",
        "source-extraction": "Kimi 100% TP (n=23). Strong primary. No recorded FPs in this cohort.",
        "adversarial-kill": "Minimax 100% TP (n=23). Strong primary for OOS/kill passes.",
    }
    if task_type in WATCH_OUTS:
        lines += ["", "## Watch-out notes", "", f"> {WATCH_OUTS[task_type]}"]

    lines += [
        "", "## Honest limits", "",
        f"- n={d} decided rows. {'Preliminary guidance only (n<5).' if d < 5 else 'Heuristic, not guaranteed.'}",
        "- No per-dispatch thinking_weight field in current logs.",
        "- Data is whatever is present in `tools/calibration/llm_calibration_log.jsonl` at emit time; rerun `make agent-calibration-refresh` after appending rows.",
        "", "---", "_[[calibration/INDEX|Back to Calibration Index]]_",
    ]
    return "\n".join(lines)


def emit_incident_note(incident_id, incident):
    lines = [
        fm(
            category="calibration-incident",
            incident_id=incident_id,
            generated_at=now_utc(),
            date=incident.get("date", ""),
            severity=incident.get("severity", ""),
            providers_involved=incident.get("providers_involved", []),
            pr_refs=incident.get("pr_refs", []),
            status=incident.get("status", ""),
        ),
        "", f"# Incident: {incident_id}", "",
        f"**Date:** {incident.get('date', 'unknown')}  ",
        f"**Severity:** {incident.get('severity', 'unknown')}  ",
        f"**Providers involved:** {', '.join(incident.get('providers_involved', ['unknown']))}  ",
        f"**Status:** {incident.get('status', 'unknown')}  ",
        "", "## Summary", "", incident.get("summary", "_No summary recorded._"),
        "", "## Root cause", "", incident.get("root_cause", "_No root cause recorded._"),
        "", "## Impact", "", incident.get("impact", "_No impact recorded._"),
        "", "## Mitigation", "", incident.get("mitigation", "_No mitigation recorded._"),
        "", "## PR references", "",
    ]
    for pr in incident.get("pr_refs", []):
        lines.append(f"- {pr}")
    lines += [
        "", "## Lessons learned", "", incident.get("lessons_learned", "_No lessons recorded._"),
        "", "---", "_[[calibration/INDEX|Back to Calibration Index]]_",
    ]
    return "\n".join(lines)


def emit_routing_decision_note(date_str, decisions):
    lines = [
        fm(category="calibration-routing-decision", date=date_str,
           generated_at=now_utc(), decision_count=len(decisions)),
        "", f"# Routing Decisions - {date_str}", "",
    ]
    for dec in decisions:
        lines += [
            f"## {dec.get('title', 'Untitled')}", "",
            f"**Date:** {dec.get('date', date_str)}  ",
            f"**Task type:** `{dec.get('task_type', '?')}`  ",
            f"**Changed:** {dec.get('provider_from', '?')} → {dec.get('provider_to', '?')}  ",
            f"**Reason:** {dec.get('reason', '?')}  ",
        ]
        if ev := dec.get("evidence"):
            lines.append(f"Evidence: {ev}")
        if pr := dec.get("pr_ref"):
            lines.append(f"PR: {pr}")
        lines.append("")
    lines += ["---", "_[[calibration/INDEX|Back to Calibration Index]]_"]
    return "\n".join(lines)


def main():
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--vault-dir", default="obsidian-vault")
    ap.add_argument("--dry-run", action="store_true")
    ap.add_argument("--section", default=None,
                    choices=["index", "providers", "task-types", "incidents", "routing-decisions"])
    args = ap.parse_args()

    vault_dir = Path(args.vault_dir)
    if not vault_dir.is_absolute():
        vault_dir = REPO_ROOT / vault_dir
    vault_cal = vault_dir / "calibration"

    cal_entries = load_jsonl(CAL_LOG)
    budget_entries = load_jsonl(BUDGET_LOG)
    routing_manifest = load_routing_manifest()

    print("[agent-calibration-vault-emit] Loading data...")
    print(f"  calibration entries: {len(cal_entries)}")
    print(f"  budget entries:      {len(budget_entries)}")
    print(f"  routing manifest:    {'loaded' if routing_manifest else 'not found / no yaml dep'}")

    provider_stats = compute_provider_stats(cal_entries, budget_entries)
    task_type_stats = compute_task_type_stats(cal_entries)
    display_providers = sorted(p for p in provider_stats if p != "unknown")
    display_task_types = sorted(t for t in task_type_stats if t != "unknown")

    print(f"  providers:           {display_providers}")
    print(f"  task_types:          {display_task_types}")
    print(f"  incidents:           {len(KNOWN_INCIDENTS)}")

    if args.dry_run:
        print("\n[dry-run] No files written.")
        return 0

    (vault_cal / "providers").mkdir(parents=True, exist_ok=True)
    (vault_cal / "task-types").mkdir(parents=True, exist_ok=True)
    (vault_cal / "incidents").mkdir(parents=True, exist_ok=True)
    (vault_cal / "routing-decisions").mkdir(parents=True, exist_ok=True)

    notes_written = 0

    if args.section in (None, "index"):
        incident_ids = [inc["id"] for inc in KNOWN_INCIDENTS]
        content = emit_index(provider_stats, task_type_stats, incident_ids, ["2026-05-04", "2026-05-17"])
        path = vault_cal / "INDEX.md"
        path.write_text(content, encoding="utf-8")
        notes_written += 1
        print(f"  wrote: {display_path(path)}")

    if args.section in (None, "providers"):
        for provider in display_providers:
            stats = provider_stats[provider]
            inc_for_prov = [i for i in KNOWN_INCIDENTS if provider in i.get("providers_involved", [])]
            content = emit_provider_note(provider, stats, routing_manifest, inc_for_prov)
            safe_name = re.sub(r"[^a-zA-Z0-9._-]", "-", provider)
            path = vault_cal / "providers" / f"{safe_name}.md"
            path.write_text(content, encoding="utf-8")
            notes_written += 1
            print(f"  wrote: {display_path(path)}")

    if args.section in (None, "task-types"):
        for tt in display_task_types:
            content = emit_task_type_note(tt, task_type_stats[tt], routing_manifest)
            safe_name = re.sub(r"[^a-zA-Z0-9._-]", "-", tt)
            path = vault_cal / "task-types" / f"{safe_name}.md"
            path.write_text(content, encoding="utf-8")
            notes_written += 1
            print(f"  wrote: {display_path(path)}")

    if args.section in (None, "incidents"):
        for inc in KNOWN_INCIDENTS:
            content = emit_incident_note(inc["id"], inc)
            safe_name = re.sub(r"[^a-zA-Z0-9._-]", "-", inc["id"])
            path = vault_cal / "incidents" / f"{safe_name}.md"
            path.write_text(content, encoding="utf-8")
            notes_written += 1
            print(f"  wrote: {display_path(path)}")

    if args.section in (None, "routing-decisions"):
        content = emit_routing_decision_note("2026-05-04", ROUTING_DECISIONS_2026_05_04)
        path = vault_cal / "routing-decisions" / "2026-05-04.md"
        path.write_text(content, encoding="utf-8")
        notes_written += 1
        print(f"  wrote: {display_path(path)}")

        content = emit_routing_decision_note("2026-05-17", ROUTING_DECISIONS_2026_05_17)
        path = vault_cal / "routing-decisions" / "2026-05-17.md"
        path.write_text(content, encoding="utf-8")
        notes_written += 1
        print(f"  wrote: {display_path(path)}")

    print(f"\n[agent-calibration-vault-emit] Done. {notes_written} notes written.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
