#!/usr/bin/env python3
"""Per-contract hypothesis aggregator (handles fenced + truncated JSON)."""
import json, pathlib, re

ROOT = "/Users/wolf/auditooor-mcp/audit/corpus_tags/derived/per_contract_hypotheses"
leads = []

def extract_objects(text):
    out = []
    depth = 0
    start = -1
    in_str = False
    escape = False
    for i, c in enumerate(text):
        if escape:
            escape = False
            continue
        if c == "\\" and in_str:
            escape = True
            continue
        if c == '"':
            in_str = not in_str
            continue
        if in_str:
            continue
        if c == "{":
            if depth == 0:
                start = i
            depth += 1
        elif c == "}":
            depth -= 1
            if depth == 0 and start >= 0:
                out.append(text[start:i+1])
                start = -1
    return out

for s in pathlib.Path(ROOT).glob("*.json"):
    try:
        with open(s) as f: d = json.load(f)
        if d.get("status") != "ok":
            continue
        result = d.get("result", "")
        if not result:
            continue
        clean = result.strip()
        if clean.startswith("```"):
            lines = clean.split("\n")
            if lines[0].startswith("```"):
                lines = lines[1:]
            if lines and lines[-1].strip() == "```":
                lines = lines[:-1]
            clean = "\n".join(lines)
        objs = extract_objects(clean)
        for obj_str in objs:
            try:
                h = json.loads(obj_str)
            except Exception:
                continue
            if not isinstance(h, dict) or "hypothesis_id" not in h:
                continue
            try:
                expl = int(h.get("exploitability_score_0_to_5", 0) or h.get("exploitability_score_1_to_5", 0) or 0)
                imp = int(h.get("impact_score_0_to_5", 0) or h.get("impact_score_1_to_5", 0) or 0)
            except Exception:
                continue
            ws = d.get("task_id", "").split("_")[2] if "_" in d.get("task_id", "") else "?"
            leads.append({
                "score": expl * imp,
                "workspace": ws,
                "hypothesis_id": h.get("hypothesis_id"),
                "attack_class": h.get("attack_class", "?"),
                "root_cause": (h.get("root_cause_one_sentence") or "")[:140],
                "known_anchor": (h.get("known_corpus_anchor") or "")[:80],
                "detector_sketch": (h.get("detector_sketch") or "")[:100],
                "source_file": d.get("task_id", "")[:80],
            })
    except Exception:
        continue

leads.sort(key=lambda x: -x["score"])
print(f"Total leads extracted: {len(leads)}")
print(f"\nTop 30 highest-scored across all workspaces:")
print()
for i, l in enumerate(leads[:30], 1):
    print(f"{i:2}. [{l['score']:2}] {l['workspace']:12} {l['attack_class']:25} - {l['hypothesis_id']}")
    print(f"        {l['root_cause']}")
    print(f"        Anchor: {l['known_anchor']}")
    print()

# Save by-workspace breakdown
by_ws = {}
for l in leads:
    by_ws.setdefault(l["workspace"], 0)
    by_ws[l["workspace"]] += 1
print()
print(f"By workspace: {by_ws}")
