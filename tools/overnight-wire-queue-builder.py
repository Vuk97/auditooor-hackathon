#!/usr/bin/env python3
"""overnight-wire-queue-builder.py — build the queue that codegens runnable detectors.

For every Phase 4 review verdict promote_to_B, build one prompt asking the LLM
to produce:
  - the FULL Slither AbstractDetector .py source
  - the clean fixture .sol (re-emitted from the prior phase3 fixture-pair)
  - the vulnerable fixture .sol (ditto)

The LLM is given:
  - the detector spec (indicators, expected hits)
  - the prior phase3 fixture-pair
  - the prior phase4 adversarial-review notes
  - a REAL wave18 detector as a one-shot template
  - strict JSON output schema

Output queue: one JSONL line per detector, fed to overnight-llm-loop.sh.
"""
from __future__ import annotations

import argparse
import json
import re
import sys
import textwrap
from pathlib import Path

REPO = Path(__file__).resolve().parents[1]
TEMPLATE_PATH = REPO / "detectors" / "wave18" / "upgradeable_missing_storage_gap.py"

_FENCE_RE = re.compile(r"^\s*```(?:json|JSON|python|sol|solidity)?\s*\n(.*?)\n\s*```\s*$", re.DOTALL)


def _load_json_strip_fences(path: Path):
    raw = path.read_text(encoding="utf-8").strip()
    try:
        return json.loads(raw)
    except json.JSONDecodeError:
        pass
    m = _FENCE_RE.match(raw)
    if m:
        try:
            return json.loads(m.group(1))
        except json.JSONDecodeError:
            pass
    for opener, closer in [("{", "}"), ("[", "]")]:
        i = raw.find(opener); j = raw.rfind(closer)
        if i >= 0 and j > i:
            try:
                return json.loads(raw[i:j+1])
            except json.JSONDecodeError:
                pass
    raise json.JSONDecodeError(f"could not parse {path}", raw, 0)


def _slug(s: str) -> str:
    return re.sub(r"[^a-zA-Z0-9]+", "_", s).strip("_").lower()


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--reviews-dir", required=True,
                    help="Directory of phase4_review_*.json files.")
    ap.add_argument("--fixtures-dir", required=True,
                    help="Directory of phase3_fixture_*.json files.")
    ap.add_argument("--queue-out", required=True)
    ap.add_argument("--prompts-dir", required=True)
    ap.add_argument("--outputs-dir", required=True)
    ap.add_argument("--max-tasks", type=int, default=0,
                    help="If >0, only emit this many tasks (debug).")
    args = ap.parse_args()

    reviews_dir = Path(args.reviews_dir)
    fixtures_dir = Path(args.fixtures_dir)
    prompts_dir = Path(args.prompts_dir); prompts_dir.mkdir(parents=True, exist_ok=True)
    outputs_dir = Path(args.outputs_dir); outputs_dir.mkdir(parents=True, exist_ok=True)
    queue_path = Path(args.queue_out); queue_path.parent.mkdir(parents=True, exist_ok=True)

    template_text = TEMPLATE_PATH.read_text(encoding="utf-8")

    tasks = []
    for rf in sorted(reviews_dir.glob("phase4_review_*.json")):
        if rf.name.endswith(".stderr"):
            continue
        try:
            review = _load_json_strip_fences(rf)
        except Exception:
            continue
        if not isinstance(review, dict):
            continue
        if review.get("verdict") != "promote_to_B":
            continue
        det_id_raw = review.get("detector_id")
        if not det_id_raw:
            continue
        det_id = _slug(det_id_raw)
        ff = fixtures_dir / f"phase3_fixture_{det_id_raw}.json"
        if not ff.exists():
            continue
        try:
            fixture = _load_json_strip_fences(ff)
        except Exception:
            continue
        clean_sol = fixture.get("fixture_pair_clean_sol", "")
        vuln_sol = fixture.get("fixture_pair_vulnerable_sol", "")
        spec = fixture.get("detector_spec") or {}
        if not (clean_sol and vuln_sol and spec):
            continue

        argument = det_id.replace("_", "-")[:60]

        # Build prompt — use delimiter-based output to avoid all JSON-escape pitfalls.
        class_name = ''.join(p.capitalize() for p in det_id.split('_'))
        prompt = textwrap.dedent(f"""\
            You are converting a vetted vulnerability pattern + fixture pair
            into a RUNNABLE Slither AbstractDetector. Your output is fed
            VERBATIM through an automated parser. Use literal section
            delimiters — no JSON, no markdown fences, no escape sequences.

            === REAL WAVE18 TEMPLATE (study this exact shape, especially how it
            iterates contract.functions, state_variables_declared, inheritance,
            and uses NodeType / IR APIs — DO NOT just regex source text) ===
            {template_text}
            === END TEMPLATE ===

            === PATTERN ID ===
            {det_id}
            slither --detect ARGUMENT: {argument}
            class name (PascalCase): {class_name}

            === DETECTOR SPEC (from prior pipeline phase) ===
            {json.dumps(spec, indent=2)[:3500]}

            === REVIEW NOTES (verdict=promote_to_B) ===
            rationale: {review.get("rationale", "")[:500]}
            precision_estimate: {review.get("precision_estimate", "")}

            === CLEAN FIXTURE (your detector MUST produce 0 hits on this) ===
            {clean_sol[:5000]}

            === VULNERABLE FIXTURE (your detector MUST produce >=1 hit on this) ===
            {vuln_sol[:5000]}

            === OUTPUT FORMAT (STRICT) ===

            Output ONLY four sections, in this exact order, separated by the
            shown delimiter lines. Inside each section, write the source code
            VERBATIM with REAL newlines — no \\\\n, no escapes, no fences.

            ===BEGIN_DETECTOR_PY===
            <the full Python source for the AbstractDetector subclass>
            ===END_DETECTOR_PY===
            ===BEGIN_CLEAN_SOL===
            <the clean Solidity fixture verbatim>
            ===END_CLEAN_SOL===
            ===BEGIN_VULNERABLE_SOL===
            <the vulnerable Solidity fixture verbatim>
            ===END_VULNERABLE_SOL===
            ===BEGIN_METADATA===
            detector_id: {det_id}
            slither_argument: {argument}
            expected_clean_hits: 0
            expected_vulnerable_hits_min: {spec.get('expected_vulnerable_hits_min', 1)}
            ===END_METADATA===

            === DETECTOR REQUIREMENTS ===

            The detector .py MUST:
              1. Start with: import re; from slither.detectors.abstract_detector
                 import (AbstractDetector, DetectorClassification, DETECTOR_INFO);
                 from slither.utils.output import Output
              2. Define class {class_name}(AbstractDetector) with:
                 ARGUMENT = "{argument}"
                 HELP = "<one-line>"
                 IMPACT = DetectorClassification.HIGH or MEDIUM or LOW
                 CONFIDENCE = DetectorClassification.HIGH or MEDIUM
                 WIKI = "<url>"
                 WIKI_TITLE = "<title>"
                 WIKI_DESCRIPTION = "<multi-line ok>"
                 WIKI_EXPLOIT_SCENARIO = "<multi-line ok>"
                 WIKI_RECOMMENDATION = "<one-line>"
              3. Implement _detect(self) -> list[Output] returning hits found by:
                 iterating self.contracts, then contract.functions, then
                 function.nodes / state_variables_declared / inheritance.
                 Use the Slither IR/AST API. Avoid string regex over source code
                 unless absolutely necessary.
              4. Skip vendored/test contracts (check filename or contract name
                 against {{"test", "mock", "fixture", "helper", "script", "setup"}}).
              5. Be syntactically valid Python 3 — no triple-quoted strings
                 spanning multiple sections, no broken indentation.

            BE PRECISE. The wirer will execute your detector against both
            fixtures and reject it if clean has >0 hits or vulnerable has 0.
        """)

        prompt_path = prompts_dir / f"wire_{det_id}.txt"
        prompt_path.write_text(prompt, encoding="utf-8")

        out_path = outputs_dir / f"wire_{det_id}.json"
        tasks.append({
            "task_id": f"wire-{det_id}",
            "provider": "minimax",
            "task_type": "detector-wire",
            "prompt_path": str(prompt_path),
            "output_path": str(out_path),
            "max_tokens": 12000,
        })

    if args.max_tasks:
        tasks = tasks[: args.max_tasks]

    with queue_path.open("w") as f:
        for t in tasks:
            f.write(json.dumps(t) + "\n")

    print(f"wire queue: {queue_path} tasks={len(tasks)}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
