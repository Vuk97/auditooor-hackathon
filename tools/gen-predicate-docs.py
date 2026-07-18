#!/usr/bin/env python3
"""
gen-predicate-docs.py - autogenerate reference/PREDICATES.md (Issue #98).

Parses detectors/_predicate_engine.py for every `key == "..."` branch and
emits a Markdown reference of all DSL predicates with examples.

Usage:
    python3 tools/gen-predicate-docs.py             # writes reference/PREDICATES.md
    python3 tools/gen-predicate-docs.py --stdout    # prints to stdout
"""

import argparse
import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
ENGINE = ROOT / "detectors" / "_predicate_engine.py"
COMPILER = ROOT / "tools" / "pattern-compile.py"
OUT = ROOT / "reference" / "PREDICATES.md"


def _extract_frozenset_keys(src: str, name: str) -> list[str]:
    match = re.search(rf"\b{name}\s*=\s*frozenset\(\{{(.*?)\}}\)", src, re.S)
    if not match:
        return []
    return re.findall(r'"([^"]+)"', match.group(1))


def extract_predicates():
    src = ENGINE.read_text()
    # Extract every supported key literal from predicate branches, including:
    #   if key == "foo" or key == "bar":
    #   if key in {"foo", "bar"}:
    keys = re.findall(r'\bkey\s*==\s*"([^"]+)"', src)
    for match in re.finditer(r'\bkey\s+in\s*(\{[^}]*\}|\([^)]*\)|\[[^\]]*\])', src, re.S):
        keys.extend(re.findall(r'"([^"]+)"', match.group(1)))
    if COMPILER.exists():
        compiler_src = COMPILER.read_text(encoding="utf-8")
        keys.extend(_extract_frozenset_keys(compiler_src, "SUPPORTED_DOMAIN_PRECONDITION_KEYS"))
        keys.extend(_extract_frozenset_keys(compiler_src, "SUPPORTED_PRECONDITION_KEYS"))
        keys.extend(_extract_frozenset_keys(compiler_src, "SUPPORTED_FUNCTION_KEYS"))
    # Dedup while preserving order.
    seen = set()
    uniq = []
    for key in keys:
        if key in seen:
            continue
        seen.add(key)
        uniq.append({"key": key})
    return uniq


GROUP_MAP = {
    "function.": "Function predicates",
    "contract.": "Contract predicates",
}

EXAMPLE_SNIPPETS = {
    "function.kind": 'preconditions:\n    - function.kind: external',
    "function.name_matches": 'preconditions:\n    - function.name_matches: "^set[A-Z]"',
    "function.body_contains_regex": 'match:\n    - function.body_contains_regex: "transfer\\\\s*\\\\("',
    "function.body_not_contains_regex": 'match:\n    - function.body_not_contains_regex: "require\\\\s*\\\\("',
    "function.has_modifier": 'preconditions:\n    - function.has_modifier:\n        includes: ["onlyOwner"]',
    "function.writes_storage_matching": 'match:\n    - function.writes_storage_matching: "balance"',
    "function.reads_storage_matching": 'match:\n    - function.reads_storage_matching: "price"',
    "function.calls_function_matching": 'match:\n    - function.calls_function_matching: "^transfer$"',
    "function.is_payable": 'preconditions:\n    - function.is_payable: true',
    "function.state_mutability": 'preconditions:\n    - function.state_mutability: "view"',
    "function.has_param_of_type": 'preconditions:\n    - function.has_param_of_type: "bytes"',
    "function.has_param_name_matching": 'preconditions:\n    - function.has_param_name_matching: "amount"',
    "function.is_mutating": 'preconditions:\n    - function.is_mutating: true',
    "function.not_slither_synthetic": 'preconditions:\n    - function.not_slither_synthetic: true',
    "function.is_constructor": 'preconditions:\n    - function.is_constructor: false',
    "function.post_external_call_mutates_state": 'match:\n    - function.post_external_call_mutates_state: true',
    "function.post_external_call_writes_gte": 'match:\n    - function.post_external_call_writes_gte: 1',
    "function.assembly_block_matches": 'match:\n    - function.assembly_block_matches: "shl\\\\(8"',
    "function.assembly_block_not_matches": 'match:\n    - function.assembly_block_not_matches: "sstore"',
    "contract.inherits_any": 'preconditions:\n    - contract.inherits_any: ["Pausable", "ReentrancyGuard"]',
    "contract.inherits_none_of": 'preconditions:\n    - contract.inherits_none_of: ["Ownable"]',
    "contract.has_state_var_matching": 'preconditions:\n    - contract.has_state_var_matching: "_paused"',
    "contract.has_function_matching": 'preconditions:\n    - contract.has_function_matching: "^pause$"',
    "contract.has_function_body_matching": 'preconditions:\n    - contract.has_function_body_matching: "_pause\\\\("',
    "contract.has_no_function_body_matching": 'preconditions:\n    - contract.has_no_function_body_matching: "_unpause\\\\("',
    "contract.source_matches_regex": 'preconditions:\n    - contract.source_matches_regex: "IERC20"',
    "contract.source_not_contains_regex": 'preconditions:\n    - contract.source_not_contains_regex: "TODO"',
    "contract.has_state_declaration_matching": 'preconditions:\n    - contract.has_state_declaration_matching: "uint256\\\\s+rate"',
    "contract.has_no_state_declaration_matching": 'preconditions:\n    - contract.has_no_state_declaration_matching: "address\\\\s+admin"',
}


def render(predicates):
    out = []
    out.append("# DSL predicates reference")
    out.append("")
    out.append("Autogenerated from `detectors/_predicate_engine.py` by `tools/gen-predicate-docs.py`.")
    out.append("Regenerate whenever the engine changes. Every new predicate author or Sonnet agent")
    out.append("should paste this file's contents into their brief to prevent predicate invention.")
    out.append("")
    out.append(f"Total predicates: **{len(predicates)}**")
    out.append("")

    # Group
    groups = {}
    for p in predicates:
        prefix = next((k for k in GROUP_MAP if p["key"].startswith(k)), "other")
        group = GROUP_MAP.get(prefix, "Other")
        groups.setdefault(group, []).append(p)

    for group_name, items in groups.items():
        out.append(f"## {group_name}")
        out.append("")
        for p in items:
            out.append(f"### `{p['key']}`")
            example = EXAMPLE_SNIPPETS.get(p["key"])
            if example:
                out.append("")
                out.append("```yaml")
                out.append(example)
                out.append("```")
            out.append("")
    return "\n".join(out)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--stdout", action="store_true")
    args = ap.parse_args()

    preds = extract_predicates()
    doc = render(preds)
    if args.stdout:
        print(doc)
    else:
        OUT.write_text(doc)
        print(f"wrote {OUT} ({len(preds)} predicates)")


if __name__ == "__main__":
    main()
