"""
cached_domain_separator_fork_stale.py — Custom Slither detector (wave18 promote).

Pattern (P15 — Nukem + Mina Bridge, "EIP-712 Replay on Fork";
PR #121 A1 — promoted from `wave17_graveyard_reactivated/` per the Codex
detector-backfill plan in docs/DETECTOR_BACKFILL_ENGAGEMENT_4_5.md):
    _DOMAIN_SEPARATOR / DOMAIN_SEPARATOR / _CACHED_DOMAIN_SEPARATOR is cached
    as an `immutable` state variable at deploy time. If the chain forks, the
    cached separator reflects the pre-fork chain-id. Signatures valid on chain A
    become replayable on chain B. Standard OZ EIP712 avoids this by re-deriving
    the separator whenever block.chainid changes.

Detection strategy:
    1. Find `immutable` state variables whose name matches the DOMAIN_SEPARATOR
       pattern (name contains "domain" AND "sep", case-insensitive; OR exact
       names like _CACHED_DOMAIN_SEPARATOR).
    2. NEGATIVE PRECONDITION 1 (Codex A1 spec): contract MUST NOT inherit from
       OpenZeppelin `EIP712` / `EIP712Upgradeable` (those bases re-derive the
       separator whenever block.chainid changes — safe by construction).
    3. NEGATIVE PRECONDITION 2 (Codex A1 spec): contract MUST NOT define a
       `_domainSeparatorV4()` function (that's the OZ idiom for a dynamic
       chain-id-rechecking accessor; if present, the contract is using the
       safe pattern even without inheriting OZ).
    4. Check whether the contract has a dynamic re-derivation path: any
       non-constructor function that reads block.chainid inside an IF/require
       conditional node (NodeType.IF or contains_require_or_assert()).
    5. If immutable domain-separator var found AND no OZ inheritance AND no
       `_domainSeparatorV4` AND no dynamic re-derivation path → flag.

Key IR observations (from fixture inspection):
    - Vulnerable: block.chainid only appears in the constructor (sets the
      immutable). The verify() function reads DOMAIN_SEPARATOR directly.
    - Clean: block.chainid appears in _domainSeparatorV4() in a NodeType.IF
      node — the standard OZ pattern of `if (block.chainid == _CACHED_CHAIN_ID)`
      before returning cached or rebuilt separator.

Dedup check (slither --list-detectors | grep -iE 'domain|separator|immutable|fork|cache'):
    - domain-separator-collision (#30): 4-byte selector collision — different.
    - immutable-states (#99): suggests making state vars immutable — opposite.
    - eip712-domain-missing-chainid (wave4 custom): missing chainid in
      DOMAIN_SEPARATOR initialization — complementary. This detector targets the
      IMMUTABLE CACHING pattern, not just missing chainid.
    NOVEL (no builtin covers cached-immutable + no-dynamic-rederive pattern).

Source: reference/corpus_mined/slice_af.md — Nukem Loans / Mina Bridge P15.
"""

import re
import sys as _sys
from pathlib import Path as _Path
_sys.path.insert(0, str(_Path(__file__).resolve().parent.parent))
from _template_utils import is_vendored_or_test_contract

from slither.detectors.abstract_detector import (
    AbstractDetector,
    DetectorClassification,
    DETECTOR_INFO,
)
from slither.core.cfg.node import NodeType
from slither.utils.output import Output

# Regex: variable name looks like a domain separator cache
_DOMAIN_SEP_NAME_RE = re.compile(
    r'(?i)(domain.{0,8}sep|cached.{0,8}domain)',
)

# OZ EIP712 base contracts that implement the dynamic chain-id recheck idiom.
# Inheriting any of these means the contract is using the safe pattern.
_OZ_EIP712_BASES = (
    "EIP712",
    "EIP712Upgradeable",
)

SKIP_KEYWORDS = ("test", "mock", "setup", "fixture", "helper", "deploy", "script")


def _is_domain_sep_immutable(sv) -> bool:
    """True if sv is an immutable state variable with a domain-separator name."""
    if not getattr(sv, "is_immutable", False):
        return False
    return _DOMAIN_SEP_NAME_RE.search(sv.name or "") is not None


def _inherits_oz_eip712(contract) -> bool:
    """Codex A1 negative precondition: contract inherits OZ EIP712 / EIP712Upgradeable.

    OZ's EIP712 base caches chainid + separator in the constructor and
    re-derives the separator inside `_domainSeparatorV4()` whenever
    `block.chainid != _cachedChainId`. Inheriting it = safe pattern.
    """
    try:
        for base in contract.inheritance or []:
            if getattr(base, "name", "") in _OZ_EIP712_BASES:
                return True
    except Exception:
        return False
    return False


def _defines_domain_separator_v4(contract) -> bool:
    """Codex A1 negative precondition: contract defines `_domainSeparatorV4()`.

    Even without OZ inheritance, presence of this function name signals the
    OZ-style dynamic accessor — assume safe and don't flag.
    """
    try:
        for fn in contract.functions:
            if fn.name == "_domainSeparatorV4":
                return True
    except Exception:
        return False
    return False


def _function_has_dynamic_chainid_check(function) -> bool:
    """True if any non-entrypoint node in function reads block.chainid inside
    a conditional (IF node or require/assert node). This is the OZ EIP712
    pattern: `if (block.chainid == _CACHED_CHAIN_ID) { ... }`.
    """
    for node in function.nodes:
        # Skip entry/exit plumbing nodes
        if node.type not in (NodeType.IF, NodeType.EXPRESSION, NodeType.RETURN):
            if not node.contains_require_or_assert():
                continue
        is_conditional = (
            node.type == NodeType.IF
            or node.contains_require_or_assert()
        )
        if not is_conditional:
            continue
        for sv in node.solidity_variables_read:
            if sv.name == "block.chainid":
                return True
    return False


def _contract_has_dynamic_rederivation(contract) -> bool:
    """True if the contract (including inherited functions) has any non-constructor
    function that performs a dynamic block.chainid check — the OZ safe pattern.
    """
    # Check all functions visible on the contract (includes inherited)
    for fn in contract.functions:
        if fn.is_constructor:
            continue
        if _function_has_dynamic_chainid_check(fn):
            return True
    return False


class CachedDomainSeparatorForkStale(AbstractDetector):
    """Detect immutable DOMAIN_SEPARATOR with no dynamic re-derivation on fork."""

    ARGUMENT = "cached-domain-separator-fork-stale"
    HELP = (
        "Immutable DOMAIN_SEPARATOR cached at deploy time — stale after chain fork, "
        "no dynamic re-derivation path found"
    )
    IMPACT = DetectorClassification.MEDIUM
    CONFIDENCE = DetectorClassification.MEDIUM

    WIKI = "https://github.com/Vuk97/auditooor/blob/main/reference/bug_patterns_observed.md"
    WIKI_TITLE = "Cached Immutable DOMAIN_SEPARATOR Stale on Fork (P15)"
    WIKI_DESCRIPTION = (
        "An EIP-712 DOMAIN_SEPARATOR is stored as an `immutable` state variable, "
        "locking in the chain-id at deploy time. After a chain fork, the cached "
        "separator reflects the original chain-id on both branches. Signatures "
        "accepted as valid on chain A are therefore also accepted on chain B. "
        "OpenZeppelin's EIP712 base contract avoids this by comparing block.chainid "
        "to the cached chain-id at the start of every signature verification and "
        "re-deriving the separator when they differ."
    )
    WIKI_EXPLOIT_SCENARIO = """
```solidity
bytes32 public immutable DOMAIN_SEPARATOR;
constructor() {
    DOMAIN_SEPARATOR = keccak256(
        abi.encode(TYPE_HASH, keccak256("MyProtocol"), block.chainid, address(this))
    );
}
function verify(bytes32 digest, uint8 v, bytes32 r, bytes32 s) external {
    bytes32 full = keccak256(abi.encodePacked(hex"1901", DOMAIN_SEPARATOR, digest));
    address signer = ecrecover(full, v, r, s);
    require(signer != address(0));
    // ... process
}
```
After a hard fork (chain-id unchanged on both branches):
1. User signs a message on chain A (e.g. a token approval).
2. Attacker replays the same signed message on chain B.
3. DOMAIN_SEPARATOR is identical on both branches — signature verifies — action executes."""
    WIKI_RECOMMENDATION = (
        "Use OpenZeppelin's EIP712 base contract which caches the chain-id alongside "
        "the separator and re-derives both when block.chainid changes. Alternatively, "
        "implement a `_domainSeparatorV4()` view that checks "
        "`if (block.chainid == _cachedChainId) return _cachedSeparator; "
        "else return _buildDomainSeparator();`."
    )

    def _detect(self) -> list[Output]:
        results: list[Output] = []

        for contract in self.contracts:
            if any(k in contract.name.lower() for k in SKIP_KEYWORDS):
                continue
            if is_vendored_or_test_contract(contract):
                continue

            # Find immutable state variables that look like a DOMAIN_SEPARATOR cache
            cached_vars = [
                sv for sv in contract.state_variables_declared
                if _is_domain_sep_immutable(sv)
            ]
            if not cached_vars:
                continue

            # Codex A1 negative precondition 1: skip OZ EIP712 inheritors
            if _inherits_oz_eip712(contract):
                continue

            # Codex A1 negative precondition 2: skip contracts that already
            # expose the OZ-style `_domainSeparatorV4()` accessor
            if _defines_domain_separator_v4(contract):
                continue

            # If the contract has a dynamic re-derivation path (OZ safe pattern), skip
            if _contract_has_dynamic_rederivation(contract):
                continue

            for sv in cached_vars:
                info: DETECTOR_INFO = [
                    "Contract ",
                    contract,
                    " caches ",
                    sv,
                    " as an immutable state variable with no dynamic re-derivation "
                    "on chain-id change. After a hard fork, signatures valid on one "
                    "chain can be replayed on the other.\n",
                ]
                results.append(self.generate_result(info))

        return results
