#!/usr/bin/env python3
"""Sidecar quality audit batch: ask mimo to score quality 1-5 + flag FPs.

Iterates existing TOK-A enrichment sidecars (those with non-empty result),
extracts the original finding_line + the mined JSON result, asks mimo:
- quality_score 1-5
- is_false_positive yes/no
- if FP: false_positive_reason
- one suggested improvement

Sampling: takes a stratified random sample to keep volume manageable.
"""
import json, pathlib, random, sys

ROOT = "/Users/wolf/auditooor-mcp/audit/corpus_tags/derived/tok_a_enrichment"
OUT = sys.argv[1] if len(sys.argv) > 1 else "/tmp/sidecar_quality_audit_batch.jsonl"
SAMPLE_PER_CORPUS = int(sys.argv[2]) if len(sys.argv) > 2 else 100

PROMPT = """You are auditing the quality of a corpus-mining enrichment record.

Original finding (one-line excerpt from public audit corpus):
{finding_line}

Mined enrichment record (JSON):
{mined_json}

Output ONLY a JSON object:
- "quality_score_1_to_5": integer (1=incorrect/contradicts source, 5=accurate+useful)
- "is_false_positive": "yes" | "no"
- "fp_reason": string (only if "yes"; otherwise empty string)
- "suggested_improvement": one sentence (always required)
- "attack_class_canonical_check": "matches"|"mismatches"|"unverifiable" (does the attack_class in the mined record match the canonical taxonomy for what the finding describes?)

No prose outside JSON. No markdown fences."""

random.seed(42)
records = []
for corpus_dir in pathlib.Path(ROOT).iterdir():
    if not corpus_dir.is_dir():
        continue
    sidecars = sorted(corpus_dir.glob("*.json"))
    random.shuffle(sidecars)
    sample = sidecars[:SAMPLE_PER_CORPUS]
    for s in sample:
        try:
            with open(s) as f:
                d = json.load(f)
        except Exception:
            continue
        result = d.get("result")
        if not result or len(result) < 50:
            continue
        task = {
            "task_id": f"sidecar_quality_{corpus_dir.name}_{s.stem}",
            "task_type": "sidecar_quality_audit",
            "prompt": PROMPT.format(
                finding_line=d.get("task_id", s.stem)[:300],
                mined_json=result[:1500],
            ),
            "max_input_tokens": 1800,
            "max_output_tokens": 400,
            "verification_tier_target": "tier-3-synthetic-taxonomy-anchored",
            "meta": {
                "source_sidecar": str(s),
                "source_corpus": corpus_dir.name,
                "generator": "sidecar-quality-audit",
            },
        }
        records.append(task)

out_path = pathlib.Path(OUT)
out_path.parent.mkdir(parents=True, exist_ok=True)
with open(out_path, "w") as fh:
    for r in records:
        fh.write(json.dumps(r) + "\n")
print(json.dumps({"records_emitted": len(records), "output_path": str(out_path)}))
