"""
DRAFT_solidity_msgvalue.py

# DRAFT: auto-generated sibling for solidity-msgvalue (source side: solidity).
# Review required before enabling. Do NOT add to test_detectors.sh yet.

BUG_CLASS: solidity-msgvalue
description: EVM msg.value / payable handling — Solidity-specific

Auto-translated from: reference/patterns.dsl/glider-payable-bridge-entry-no-msgvalue-check.yaml
"""
from __future__ import annotations

import re

from _util import source_nocomment


def run(tree, source: bytes, filepath: str):
    hits = []
    module_nc = source_nocomment(source)
    entry = re.search(
        r"(?i)pub\s+fn\s+"
        r"(initiate_transfer|initiate_transfer_with_fee|submit_transfer|cross_chain_transfer|bridge|send_to_l1|send_to_l2)\b",
        module_nc,
    )
    if entry is None:
        return hits
    if not re.search(r"(?i)\b(attached_value|msg_value|payment|deposit_value)\b", module_nc):
        return hits
    if not re.search(r"(?is)\b(?:[\w:]+\.)?transfer\s*\(.*?(?:amount|fee|forwarded|total|value)", module_nc):
        return hits
    if re.search(
        r"(?is)(assert(?:_eq)?!\s*\([^)]*(?:attached_value|msg_value|payment|deposit_value)[^)]*(?:amount|fee|forwarded|total|value)|"
        r"if\s+[^{};\n]*(?:attached_value|msg_value|payment|deposit_value)\s*(?:<|!=|==)\s*[^{};\n]*(?:amount|fee|forwarded|total|value)\s*\{[^{}]{0,120}(?:panic!|return|Err\s*\())",
        module_nc,
    ):
        return hits
    name = entry.group(1)
    line = module_nc[:entry.start()].count("\n") + 1
    snippet = " ".join(module_nc[entry.start():].split())[:160]
    hits.append({
        "severity": "high",
        "line": line,
        "col": 0,
        "snippet": snippet,
        "message": (
            f"pub fn `{name}` looks like a bridge-style native-asset "
            "entrypoint that forwards contract funds using amount/fee "
            "inputs without first checking the attached payment covers "
            "the forwarded value."
        ),
    })

    return hits


# --- Source-side excerpt (reference only) ------------------------------------
# # Auto-migrated by tools/dsl-migration-helper.py 2026-04-19 | pattern: glider-payable-bridge-entry-no-msgvalue-check | source: hexens-glider/draining-eth-using-flat-fee-without-msgvalue-check | severity: HIGH | confidence: MEDIUM |  | preconditions: |   - contract.source_matches_regex: 'initiateTransfer|submitTra
