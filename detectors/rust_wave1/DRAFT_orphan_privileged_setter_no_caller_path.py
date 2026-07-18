"""
DRAFT_orphan_privileged_setter_no_caller_path.py

# DRAFT: auto-generated sibling for orphan-privileged-setter-no-caller-path (source side: solidity).
# Review required before enabling. Do NOT add to test_detectors.sh yet.

BUG_CLASS: orphan-privileged-setter-no-caller-path
description: Privileged rotation setter (changeDAO/setOwner/rotateAdmin) is gated by only<Role> but the authorized caller contract has no function that routes to it — setter is unreachable, admin rotation permanently bricked (Solodit #3906 Vader changeDAO); assisted-review flag, reviewer must confirm reachability

Auto-translated from: reference/patterns.dsl/orphan-privileged-setter-no-caller-path.yaml
"""
from __future__ import annotations

import re

from _util import source_nocomment


_SETTER_RE = re.compile(
    r"(?is)pub\s+fn\s+"
    r"(?P<name>(?:change|set|rotate|update|transfer)_(?:dao|owner|admin|governance|controller|timelock|guardian|council))"
    r"\s*\([^)]*\)\s*\{(?P<body>.*?)\}"
)


def run(tree, source: bytes, filepath: str):
    hits = []
    module_nc = source_nocomment(source)

    for match in _SETTER_RE.finditer(module_nc):
        name = match.group("name")
        body_text = match.group("body")
        if not re.search(rf"(?i)(assert|ensure|only)_(?:dao|owner|admin|governance|controller|timelock|guardian|council)\s*\(", body_text):
            continue
        if not re.search(r"(?i)(?:cfg|self)\.(?:dao|owner|admin|governance|controller|timelock|guardian|council)\s*=", body_text):
            continue
        call_sites = len(re.findall(rf"\b{name}\s*\(", module_nc))
        if call_sites > 1:
            continue
        line = module_nc[:match.start()].count("\n") + 1
        hits.append({
            "severity": "medium",
            "line": line,
            "col": 0,
            "snippet": " ".join(match.group(0).split())[:160],
            "message": (
                f"pub fn `{name}` looks like a privileged admin-rotation "
                "setter with an auth guard and direct role write, but this "
                "module shows no additional call path into that setter. "
                "If the authorized role-holder contract cannot route to it, "
                "rotation is orphaned and effectively bricked."
            ),
        })

    return hits


# --- Source-side excerpt (reference only) ------------------------------------
# pattern: orphan-privileged-setter-no-caller-path | source: solodit-3906-code4rena-vader-protocol-changedao | severity: HIGH | confidence: LOW | tier: B | preconditions: |   - contract.source_matches_regex: '(?i)(DAO|Governance|Owner|Admin|Controller|Timelock|Council|Guardian)' | match: |   - function.kind: external
