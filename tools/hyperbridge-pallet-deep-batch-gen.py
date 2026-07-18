#!/usr/bin/env python3
"""Hyperbridge pallet-level deep adversarial-hypothesis batch.

For each Substrate pallet in hyperbridge, read up to 8KB of lib.rs and
ask mimo to emit 8 high-priority attack hypotheses tailored to Substrate-
specific bug shapes (unbounded weight, on_initialize panics, dispatch_call
auth bypass, storage migration data corruption, fishermen / consensus
incentive economic exploits, etc).
"""
import json, pathlib, sys, glob

PALLETS = sorted(glob.glob("/Users/wolf/audits/hyperbridge/src/hyperbridge/modules/pallets/*/src/lib.rs"))
OUT = sys.argv[1] if len(sys.argv) > 1 else "/tmp/hyperbridge_pallet_deep_batch.jsonl"

PROMPT = """You are an expert Substrate / Polkadot security researcher analyzing a parachain pallet for high-severity attack vectors.

Pallet: {pallet_name}
File: {file_path}

Pallet source (first 8KB):
```rust
{file_content}
```

Generate EXACTLY 8 high-confidence attack hypotheses for this pallet. Prioritise:
- Unbounded weight / DoS via unbounded loops in dispatchables
- Storage migration data corruption
- on_initialize / on_finalize panics that halt block production
- dispatch_call auth bypass (ensure_signed/ensure_root absent or wrong)
- Cross-chain message replay (missing nonce, missing chain-id binding)
- Economic incentive misalignment (slashing/reward bugs, fee escape hatches)
- BoundedVec overflow / append-beyond-cap edge cases
- Hooks calling external (non-pallet) code with arbitrary input

For each hypothesis output JSON:
- "hypothesis_id": short slug
- "attack_class": one of {{theft, freeze, governance-takeover, dos, griefing, oracle-manipulation, cross-chain-replay, signature-malleability, state-corruption, privilege-escalation, unbounded-weight, slashing-bypass, fee-escape, runtime-panic-halt}}
- "substrate_specific_anchor": one of {{dispatchable-auth, on_initialize-panic, BoundedVec-overflow, storage-migration-corruption, weight-unbounded, hooks-external-call, cross-chain-nonce-missing, slashing-grace-bypass, fishermen-payout-replay}}
- "exploitability_1_to_5": int
- "impact_1_to_5": int
- "where_to_hunt": list of 3 file:func:line hints WITHIN this pallet
- "detector_sketch": one-line regex/grep
- "minimum_evidence_to_file": list of 2-3 source-anchor lines

Return ONLY a JSON array of 8 objects."""

records = []
for i, p in enumerate(PALLETS, 1):
    pallet_path = pathlib.Path(p)
    pallet_name = pallet_path.parent.parent.name  # parents/pallets/{name}/src/lib.rs
    try:
        content = pallet_path.read_text(encoding="utf-8", errors="replace")[:8000]
    except Exception:
        continue
    if len(content) < 200:
        continue
    task = {
        "task_id": f"hyperbridge_pallet_{pallet_name}_{i:02d}",
        "task_type": "hyperbridge_pallet_deep",
        "prompt": PROMPT.format(
            pallet_name=pallet_name,
            file_path=str(pallet_path),
            file_content=content,
        ),
        "max_input_tokens": 9000,
        "max_output_tokens": 3000,
        "verification_tier_target": "tier-3-synthetic-taxonomy-anchored",
        "meta": {
            "pallet_name": pallet_name,
            "source_path": str(pallet_path),
            "generator": "hyperbridge-pallet-deep",
        },
    }
    records.append(task)

out_path = pathlib.Path(OUT)
with open(out_path, "w") as fh:
    for r in records:
        fh.write(json.dumps(r) + "\n")
print(json.dumps({"records_emitted": len(records), "output_path": str(out_path)}))
