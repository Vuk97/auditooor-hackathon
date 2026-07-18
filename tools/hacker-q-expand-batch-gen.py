#!/usr/bin/env python3
"""Custom mimo batch: hacker-question expansion.

Reads audit/corpus_tags/derived/hacker_questions_library.jsonl (7494 records),
emits one mimo task per question asking for:
- 3 sub-question variants
- 3 additional grep patterns
- 1 detection-difficulty self-assessment
- 1 source-anchor explanation paragraph
"""
from __future__ import annotations
import json, pathlib, sys

LIB = "/Users/wolf/auditooor-mcp/audit/corpus_tags/derived/hacker_questions_library.jsonl"
OUT = sys.argv[1] if len(sys.argv) > 1 else "/tmp/hacker_q_expand_batch.jsonl"
SAMPLE_LIMIT = int(sys.argv[2]) if len(sys.argv) > 2 else 0  # 0 = all

PROMPT = """You are an expert smart-contract security researcher expanding a hacker-question into deeper detection material.

Existing hacker question:

  question_id: {qid}
  question_text: {qtext}
  attack_class_anchor: {anchor}
  current_grep_patterns: {greps}
  scope: {scope}

Output ONLY a JSON object with these fields:
- "sub_question_variants": list of 3 distinct question rephrasings that approach the SAME attack class from different angles (e.g. caller-side, callee-side, state-transition-side)
- "additional_grep_patterns": list of 3 NEW regex/grep patterns that catch the same vulnerability shape but in different code idioms
- "detection_difficulty_1_to_5": integer (1=trivial-grep, 5=requires-deep-control-flow-analysis)
- "false_positive_warnings": list of 2 common code patterns that would TRIGGER the grep but are NOT actually the bug
- "source_anchor_explanation": one paragraph (<=4 sentences) explaining the original case study and why this question class catches related future bugs

No prose outside the JSON. No markdown fences."""

records = []
with open(LIB) as f:
    for i, line in enumerate(f, 1):
        d = json.loads(line)
        records.append(d)
        if SAMPLE_LIMIT and i >= SAMPLE_LIMIT:
            break

out_path = pathlib.Path(OUT)
out_path.parent.mkdir(parents=True, exist_ok=True)
with open(out_path, "w") as fh:
    for i, q in enumerate(records, 1):
        task = {
            "task_id": f"hacker_q_expand_{i:05d}",
            "task_type": "hacker_q_expand",
            "prompt": PROMPT.format(
                qid=q.get("question_id"),
                qtext=q.get("question_text", "")[:600],
                anchor=q.get("attack_class_anchor", "unknown"),
                greps=", ".join(q.get("grep_patterns", []))[:300],
                scope=q.get("scope_specificity", "unknown"),
            ),
            "max_input_tokens": 1500,
            "max_output_tokens": 800,
            "verification_tier_target": "tier-3-synthetic-taxonomy-anchored",
            "meta": {
                "source_question_id": q.get("question_id"),
                "attack_class_anchor": q.get("attack_class_anchor"),
                "generator": "hacker-q-expand",
                "generator_version": "v1",
            },
        }
        fh.write(json.dumps(task) + "\n")

print(json.dumps({"records_emitted": len(records), "output_path": str(out_path)}))
