"""
rust_rpc_multi_address_no_count_cap.py

Flags a `valid_addresses` validation function (or structural equivalent) that:
  1. Iterates over a caller-supplied slice/vec of address strings via
     `.iter().map(|..| ..parse()..)`.
  2. Collects the parsed results into a set/vec without checking
     `self.addresses().len() <= MAX_ADDRESSES_PER_REQUEST` (or any equivalent
     per-request address-count cap).
  3. Is called from RPC handlers that pass the uncapped set directly to a
     state-layer request (AddressBalance, TransactionIds, UtxosByAddresses).

Root cause: any caller can supply an arbitrarily long address list; the node
will parse and look up every address, consuming unbounded CPU and memory.

Real zebra occurrence:
  zebra-rpc/src/methods.rs  trait ValidateAddresses::valid_addresses (line ~3527)
  Three handlers call it with no upstream len guard:
    get_address_balance (~line 1135)
    get_address_tx_ids  (~line 2051)
    get_address_utxos   (~line 2097)

Severity: high
Rubric: Non-distributed DoS against an individual node or wallet.
"""

from __future__ import annotations

import re

from _util import (
    body_text_nocomment,
    fn_body,
    fn_name,
    function_items,
    in_test_cfg,
    line_col,
    snippet_of,
    text_of,
    IDENT,
)

# ---------------------------------------------------------------------------
# Signal 1: function name matches the validation entry point
# Matches: valid_addresses, validate_addresses, check_addresses, parse_addresses
# ---------------------------------------------------------------------------
_FN_NAME_RE = re.compile(
    r"^(?:valid|validate|check|parse|sanitize)_address(?:es)?$"
)

# ---------------------------------------------------------------------------
# Signal 2: iterates over address strings via .iter().map(|x| x.parse())
# The canonical shape:
#   self.addresses().iter().map(|address| address.parse()...)
#   or any variant: iter().map(|a| a.parse()), iter().map(|s| s.parse())
# ---------------------------------------------------------------------------
_ITER_PARSE_RE = re.compile(
    r"\.iter\s*\(\s*\)\s*\.map\s*\(\s*\|"
    r"[\w]+\|\s*[\w]+\s*\.\s*parse\s*\(",
    re.DOTALL,
)

# Also accept the closure using a block:  .map(|addr| { addr.parse()... })
_ITER_PARSE_BLOCK_RE = re.compile(
    r"\.iter\s*\(\s*\)\s*\.map\s*\(\s*\|[\w]+\|\s*\{[^}]{0,200}\.parse\s*\(",
    re.DOTALL,
)

# ---------------------------------------------------------------------------
# Signal 3: collects into a HashSet / BTreeSet / Vec (the result is used
# downstream as a state-layer request argument).
# Handles .collect(), .collect::<Vec<_>>(), .collect::<Result<HashSet<_>>>() etc.
# The nested-generic form `<Result<_>>` defeats a simple [^>]* character class,
# so we just look for `.collect` as a word boundary anchor.
# ---------------------------------------------------------------------------
_COLLECT_RE = re.compile(r"\.collect\b")

# ---------------------------------------------------------------------------
# Guard patterns: any of these indicate a per-request address-count cap
# ---------------------------------------------------------------------------
_GUARD_PATTERNS = [
    # Explicit len comparison: addresses.len() > N  or  len > MAX_ADDR
    r"(?:addresses|addrs|addr_list|strs|strings)\s*(?:\(\s*\))?\s*\.len\s*\(\s*\)\s*(?:>|>=|<|<=)",
    r"\.len\s*\(\s*\)\s*(?:>|>=|<|<=)\s*\w",
    # Constant-name guards
    r"\bMAX_ADDRESSES\b",
    r"\bMAX_ADDRESS_COUNT\b",
    r"\bMAX_ADDRS\b",
    r"\bADDRESS_LIMIT\b",
    r"\bMAX_ADDRESSES_PER_REQUEST\b",
    r"\blimit\s*=",
    # Error strings indicating a count check
    r"too\s+many\s+address",
    r"address.*(?:limit|cap|max)\s+exceeded",
    r"(?:limit|cap|max).*address",
    r"exceeds\s+maximum",
]
_GUARD_RES = [re.compile(p, re.IGNORECASE) for p in _GUARD_PATTERNS]


def _has_count_cap_guard(body_text: str) -> bool:
    return any(g.search(body_text) for g in _GUARD_RES)


def run(tree, source: bytes, filepath: str):
    hits = []

    for fn in function_items(tree.root_node):
        if in_test_cfg(fn, source):
            continue

        name = fn_name(fn, source)

        # Signal 1: function name must match the validation-entry-point pattern
        if not _FN_NAME_RE.match(name):
            continue

        body = fn_body(fn)
        if body is None:
            continue

        body_text = body_text_nocomment(body, source)

        # Signal 2: must iterate over address strings via .iter().map(|x| x.parse())
        if not (_ITER_PARSE_RE.search(body_text) or _ITER_PARSE_BLOCK_RE.search(body_text)):
            continue

        # Signal 3: must collect the results (no partial-take, no early exit per entry)
        if not _COLLECT_RE.search(body_text):
            continue

        # Guard: if there IS a len/count cap, this is not vulnerable
        if _has_count_cap_guard(body_text):
            continue

        line, col = line_col(body)
        hits.append({
            "severity": "high",
            "line": line,
            "col": col,
            "snippet": snippet_of(body, source),
            "message": (
                f"fn `{name}` iterates over a caller-supplied address list "
                "via `.iter().map(|addr| addr.parse()).collect()` without "
                "checking `addresses.len() <= MAX_ADDRESSES_PER_REQUEST`. "
                "An attacker can submit a request with thousands of addresses, "
                "forcing unbounded parse-and-lookup work and causing node DoS. "
                "Add a per-request address count cap before the iteration."
            ),
        })

    return hits
