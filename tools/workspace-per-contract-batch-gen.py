#!/usr/bin/env python3
"""Custom mimo batch generator: per-contract adversarial hypothesis mining.

Walks workspace src/ trees, extracts contract names + first ~80 lines of each
Solidity/Rust file, and emits a mimo-compatible JSONL batch asking for 5
high-confidence attack hypotheses per contract based on the corpus of
acknowledged real-world exploit families.

Output: /tmp/per_contract_<ws>_batch_<ts>.jsonl
"""
from __future__ import annotations
import argparse, datetime, json, pathlib, sys
from typing import List

PROMPT_TEMPLATE = """You are an expert smart-contract security researcher analyzing a target for high-severity attack vectors.

Target workspace: {workspace}
Target file: {file_path}
File extension: {ext}

File content (first 80 lines):
```
{file_content}
```

Generate EXACTLY 5 high-confidence attack hypotheses for this contract/module, prioritising:
- Direct loss of funds
- Permanent freezing
- Theft / unauthorized state transition
- Cross-chain replay / message-injection (if bridge code)
- Multi-actor griefing with non-self impact

For each hypothesis output JSON object with fields:
- hypothesis_id: short slug (e.g. "missing-slippage-on-deposit")
- attack_class: one of {{theft, freeze, governance-takeover, dos, griefing, yield-redistribution, precision-loss, privilege-escalation, oracle-manipulation, reentrancy, cross-chain-replay, signature-malleability, calldata-tampering, state-corruption}}
- root_cause_one_sentence: <80 chars
- exploitability_score_0_to_5: integer
- impact_score_0_to_5: integer
- known_corpus_anchor: cite one existing known exploit pattern this resembles (e.g. "Curve readonly reentrancy 2023", "Wormhole signature replay 2022", "Nomad message replay 2022")
- detector_sketch: 1-line regex or static-analysis pattern to surface this
- minimum_evidence_to_file: list of 2-3 source-anchor lines (file:func ranges) needed to confirm

Return ONLY a JSON array of 5 objects. No prose. No markdown fences."""

def gen_batch(workspace_dir: str, workspace_name: str, exts: List[str], out_path: str, max_files: int):
    ws = pathlib.Path(workspace_dir)
    src_dirs = [ws / "src", ws]
    files = []
    for sd in src_dirs:
        if sd.is_dir():
            for ext in exts:
                files.extend(sd.rglob(f"*.{ext}"))
            break
    # Filter out interface / test / mock files (lower-value)
    files = [f for f in files if "interface" not in str(f).lower() and "/test" not in str(f).lower() and "/mock" not in str(f).lower()]
    files = sorted(set(files))[:max_files]
    out = pathlib.Path(out_path)
    out.parent.mkdir(parents=True, exist_ok=True)
    n = 0
    with open(out, "w", encoding="utf-8") as fh:
        for i, f in enumerate(files, 1):
            try:
                lines = f.read_text(encoding="utf-8", errors="replace").splitlines()[:80]
            except Exception:
                continue
            if len(lines) < 5:
                continue
            content = "\n".join(lines)[:6000]
            task = {
                "task_id": f"per_contract_{workspace_name}_{i:04d}",
                "task_type": "per_contract_adv_hypothesis",
                "prompt": PROMPT_TEMPLATE.format(
                    workspace=workspace_name,
                    file_path=str(f.relative_to(ws.parent) if ws.parent in f.parents else f),
                    ext=f.suffix.lstrip("."),
                    file_content=content,
                ),
                "max_input_tokens": 4000,
                "max_output_tokens": 1500,
                "verification_tier_target": "tier-3-synthetic-taxonomy-anchored",
                "meta": {
                    "source_path": str(f),
                    "workspace": workspace_name,
                    "generator": "workspace-per-contract",
                    "generator_version": "v1",
                },
            }
            fh.write(json.dumps(task) + "\n")
            n += 1
    print(json.dumps({"workspace": workspace_name, "batch_path": str(out), "tasks_emitted": n}))

if __name__ == "__main__":
    ts = datetime.datetime.utcnow().strftime("%Y%m%dT%H%M%SZ")
    gen_batch("/Users/wolf/audits/morpho-midnight", "morpho-midnight", ["sol"], f"/tmp/per_contract_morpho_midnight_{ts}.jsonl", 120)
    gen_batch("/Users/wolf/audits/hyperbridge", "hyperbridge", ["rs", "sol"], f"/tmp/per_contract_hyperbridge_{ts}.jsonl", 120)
    gen_batch("/Users/wolf/audits/near", "near", ["rs"], f"/tmp/per_contract_near_{ts}.jsonl", 120)
    gen_batch("/Users/wolf/audits/dydx", "dydx", ["go", "rs"], f"/tmp/per_contract_dydx_{ts}.jsonl", 120)
    gen_batch("/Users/wolf/audits/zebra", "zebra", ["rs"], f"/tmp/per_contract_zebra_{ts}.jsonl", 120)
