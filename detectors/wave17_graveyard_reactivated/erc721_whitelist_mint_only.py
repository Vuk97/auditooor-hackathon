"""
erc721_whitelist_mint_only.py - Custom Slither detector.

Pattern (BitVault slice_ac MED - Non-Whitelisted-Owner-Holds-TroveNFT): An
ERC-721 contract enforces an ownership whitelist *only* inside `mint` (e.g.
`require(whitelist[to])`), but the contract does NOT override
`_beforeTokenTransfer` / `_update` to replicate the check. A whitelisted user
can transfer the NFT to a non-whitelisted address and bypass the policy.

Detection strategy:
    1. Find contracts that own a state var mapping whose name matches
       `whitelist|allowed|allowlist|kyc|approved(?!Spenders)` and value type
       is `bool` or `address`.
    2. The contract must declare a function named `mint`/`safeMint`/`_mint*`
       that reads that state var inside a require/assert.
    3. The contract must NOT declare (locally) `_beforeTokenTransfer`/`_update`
       with a require/assert that reads the same state var.
    4. Only flag contracts that actually look like ERC-721 - we require either
       a function named `ownerOf`, or an import/inheritance signal. We
       approximate with: contract has a function `ownerOf` OR has a function
       `safeMint` OR `_safeMint`.
    5. Flag the `mint` function with a pointer to the missing hook.

@author auditooor wave11
@pattern slice_ac BitVault TroveNFT - whitelist enforced in mint only
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
from slither.utils.output import Output


_SKIP_KEYWORDS = ("test", "mock", "fixture", "helper", "script", "setup", "deploy")

_WHITELIST_RE = re.compile(
    r"whitelist|allowlist|allowed|kyc|permitted",
    re.IGNORECASE,
)
_HOOK_NAMES = frozenset({
    "_update",
    "_beforetokentransfer",
    "_aftertokentransfer",
    "_transfer",
})
_MINT_NAMES = ("mint", "safemint", "_safemint", "_mint")


def _looks_whitelist(sv) -> bool:
    nm = (getattr(sv, "name", "") or "")
    return bool(_WHITELIST_RE.search(nm))


def _reads_wl_in_require(function, wl_vars) -> bool:
    for node in function.nodes:
        if not node.contains_require_or_assert():
            continue
        if any(sv in wl_vars for sv in node.state_variables_read):
            return True
    return False


def _looks_like_erc721(contract) -> bool:
    names = {(f.name or "").lower() for f in contract.functions_and_modifiers_declared}
    names |= {(f.name or "").lower() for f in contract.functions}
    if "ownerof" in names:
        return True
    if any(n in names for n in ("safemint", "_safemint")):
        return True
    return False


class Erc721WhitelistMintOnly(AbstractDetector):
    """Flag ERC-721 whitelists enforced in mint but not in transfer hook."""

    ARGUMENT = "erc721-whitelist-mint-only"
    HELP = (
        "ERC-721 whitelist enforced in mint() but NOT in the transfer hook - "
        "whitelisted owner can transfer the NFT to a non-whitelisted address"
    )
    IMPACT = DetectorClassification.MEDIUM
    CONFIDENCE = DetectorClassification.MEDIUM

    WIKI = "https://github.com/Vuk97/auditooor/blob/main/reference/bug_patterns_observed.md"
    WIKI_TITLE = "ERC-721 Whitelist Enforced Only In Mint"
    WIKI_DESCRIPTION = (
        "An ERC-721 contract enforces a per-address whitelist (KYC / allowlist) "
        "inside its mint function but does not override "
        "`_beforeTokenTransfer` / `_update` to replicate the check. A "
        "whitelisted user can simply transfer the token to a non-whitelisted "
        "address, bypassing the policy. Reported in BitVault TroveNFT."
    )
    WIKI_EXPLOIT_SCENARIO = """
```solidity
mapping(address => bool) public whitelist;

function mint(address to, uint256 id) external {
    require(whitelist[to], "not whitelisted");
    _safeMint(to, id);
}

// BUG: no _update override that re-checks the whitelist
```
1. Alice (whitelisted) mints the NFT.
2. Alice transfers to Bob (not whitelisted).
3. Bob now holds a trove NFT without passing any KYC gate."""
    WIKI_RECOMMENDATION = (
        "Override `_update` / `_beforeTokenTransfer` and replicate "
        "`require(whitelist[to])` so every balance change - not only mints - "
        "is gated by the whitelist."
    )

    def _detect(self) -> list[Output]:
        results: list[Output] = []

        for contract in self.contracts:
            if is_vendored_or_test_contract(contract):
                continue
            if any(k in contract.name.lower() for k in _SKIP_KEYWORDS):
                continue
            if not _looks_like_erc721(contract):
                continue

            wl_vars = {sv for sv in contract.state_variables if _looks_whitelist(sv)}
            if not wl_vars:
                continue

            mint_with_wl = None
            for f in contract.functions_and_modifiers_declared:
                nm = (f.name or "").lower()
                if not any(nm == n or nm.startswith(n) for n in _MINT_NAMES):
                    continue
                if f.is_constructor:
                    continue
                if _reads_wl_in_require(f, wl_vars):
                    mint_with_wl = f
                    break
            if mint_with_wl is None:
                continue

            hook_checks = False
            for f in contract.functions_and_modifiers_declared:
                nm = (f.name or "").lower()
                if nm not in _HOOK_NAMES:
                    continue
                if _reads_wl_in_require(f, wl_vars):
                    hook_checks = True
                    break
            if hook_checks:
                continue

            info: DETECTOR_INFO = [
                mint_with_wl,
                " enforces the whitelist on mint but ",
                contract,
                " has no _update/_beforeTokenTransfer override repeating the "
                "check - transfers bypass the whitelist.\n",
            ]
            results.append(self.generate_result(info))

        return results
