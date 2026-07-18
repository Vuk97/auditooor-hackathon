#!/usr/bin/env python3
"""Workspace-specific deep vulnerability enumeration batch for mimo.

For each workspace: read SCOPE.md + SEVERITY.md (if exist) + extract
audit-pin from .auditooor/commit_lifecycle_ledger.json, then ask mimo
to enumerate 20 most-likely vulnerability classes specific to that target
ranked by exploitability score x impact score, with concrete file:line
hunting hints.

Output: /tmp/ws_deep_enum_batch.jsonl
"""
import json, pathlib, os

WORKSPACES = [
    ("/Users/wolf/audits/morpho-midnight", "morpho-midnight"),
    ("/Users/wolf/audits/hyperbridge", "hyperbridge"),
    ("/Users/wolf/audits/near", "near"),
    ("/Users/wolf/audits/dydx", "dydx"),
    ("/Users/wolf/audits/zebra", "zebra"),
]

PROMPT = """You are an expert smart-contract security researcher producing a workspace-specific deep vulnerability enumeration for an active bug bounty.

Workspace: {workspace_name}
Target architecture overview:
{arch_summary}

SCOPE excerpt:
{scope_excerpt}

SEVERITY rubric excerpt:
{severity_excerpt}

Enumerate the 20 most-likely-to-be-true HIGH/CRITICAL vulnerability classes for this specific target, ranked by (exploitability * impact). For each, output a JSON object:

- "rank": 1-20
- "vulnerability_class": short slug
- "attack_class_anchor": one of {{theft, freeze, governance-takeover, dos, griefing, oracle-manipulation, reentrancy, cross-chain-replay, signature-malleability, calldata-tampering, state-corruption, privilege-escalation, precision-loss, mev-extraction, unbounded-iteration}}
- "rubric_row_verbatim_match": one quoted row from SEVERITY excerpt above this maps to
- "exploit_summary": 2 sentences explaining the attack
- "where_to_hunt": list of 3-5 concrete file/directory hints (e.g. "src/router/CrossChainExec.sol", "modules/ismp-relayer/src/")
- "detector_sketch": 1-line regex or static-analysis pattern
- "primacy_of_impact_score_1_to_5": integer
- "exploitability_score_1_to_5": integer
- "false_positive_warnings": list of 1-2 known FP patterns
- "minimum_evidence_to_file": list of 2-3 source-anchor lines (file:func:line ranges)
- "known_corpus_anchor": cite one disclosed similar incident (e.g. "Curve readonly reentrancy 2023", "Nomad replay 2022")

Return ONLY a JSON array of 20 objects. No prose. No markdown fences."""

records = []
for ws_path, ws_name in WORKSPACES:
    ws = pathlib.Path(ws_path)
    if not ws.is_dir():
        continue
    scope_excerpt = ""
    severity_excerpt = ""
    arch_summary = f"Target workspace: {ws_name}"
    for fn in ["SCOPE.md", "SCOPE_FINAL.md", "ASSET_PLAN_Smart_Contract.md"]:
        p = ws / fn
        if p.exists():
            scope_excerpt = p.read_text(encoding="utf-8", errors="replace")[:3000]
            break
    for fn in ["SEVERITY.md", "SEVERITY_CAPS.md"]:
        p = ws / fn
        if p.exists():
            severity_excerpt = p.read_text(encoding="utf-8", errors="replace")[:2500]
            break
    # Architecture summary: peek at top-level src/ structure
    src = ws / "src"
    if src.is_dir():
        top_subdirs = sorted([d.name for d in src.iterdir() if d.is_dir()])[:15]
        arch_summary = f"Workspace: {ws_name}; src/ top-level: {', '.join(top_subdirs[:15])}"
    elif (ws / "external").is_dir():
        top = sorted([d.name for d in (ws / "external").iterdir() if d.is_dir()])[:10]
        arch_summary = f"Workspace: {ws_name}; external/ top-level: {', '.join(top)}"

    task = {
        "task_id": f"ws_deep_enum_{ws_name}",
        "task_type": "ws_deep_enum",
        "prompt": PROMPT.format(
            workspace_name=ws_name,
            arch_summary=arch_summary,
            scope_excerpt=scope_excerpt or "(no SCOPE.md present)",
            severity_excerpt=severity_excerpt or "(no SEVERITY.md present)",
        ),
        "max_input_tokens": 6000,
        "max_output_tokens": 3500,
        "verification_tier_target": "tier-3-synthetic-taxonomy-anchored",
        "meta": {"workspace": ws_name, "source_ws": str(ws), "generator": "ws-deep-enum"},
    }
    records.append(task)

OUT = "/tmp/ws_deep_enum_batch.jsonl"
with open(OUT, "w") as fh:
    for r in records:
        fh.write(json.dumps(r) + "\n")
print(json.dumps({"records_emitted": len(records), "output_path": OUT, "workspaces": [r["meta"]["workspace"] for r in records]}))
