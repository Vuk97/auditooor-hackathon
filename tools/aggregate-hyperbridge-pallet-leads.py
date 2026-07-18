#!/usr/bin/env python3
"""Extract hyperbridge per-pallet deep hypotheses (handles truncated/fenced JSON)."""
import json, pathlib, re, os

ROOT = "/Users/wolf/auditooor-mcp/audit/corpus_tags/derived/hyperbridge_pallet_deep"
leads = []

def extract_objects(text):
    """Extract balanced {...} JSON object substrings from text."""
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
        pallet_name = os.path.basename(s).replace("hyperbridge_pallet_", "").replace(".json", "")
        # Strip fences
        clean = result.strip()
        if clean.startswith("```"):
            lines = clean.split("\n")
            if lines[0].startswith("```"):
                lines = lines[1:]
            if lines and lines[-1].strip() == "```":
                lines = lines[:-1]
            clean = "\n".join(lines)
        # Extract balanced { ... } objects
        objs = extract_objects(clean)
        for obj_str in objs:
            try:
                h = json.loads(obj_str)
            except Exception:
                continue
            if not isinstance(h, dict) or "hypothesis_id" not in h:
                continue
            try:
                expl = int(h.get("exploitability_1_to_5", 0) or 0)
                imp = int(h.get("impact_1_to_5", 0) or 0)
            except Exception:
                continue
            leads.append({
                "score": expl * imp,
                "pallet": pallet_name,
                "hypothesis_id": h.get("hypothesis_id"),
                "attack_class": h.get("attack_class", "?"),
                "substrate_anchor": h.get("substrate_specific_anchor", "?"),
                "where_to_hunt": h.get("where_to_hunt", []),
                "detector_sketch": (h.get("detector_sketch") or "")[:120],
            })
    except Exception:
        continue

leads.sort(key=lambda x: -x["score"])
print(f"Total hyperbridge pallet leads: {len(leads)}")
print()
for i, l in enumerate(leads[:30], 1):
    print(f"{i:2}. [{l['score']:2}] {l['pallet']:35} {l['attack_class']:25} - {l['hypothesis_id']}")
    print(f"        Substrate anchor: {l['substrate_anchor']}")
    if l['where_to_hunt']:
        print(f"        Hunt at: {', '.join(str(x) for x in l['where_to_hunt'][:3])}")
    print()
