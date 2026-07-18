"""
erc4626_principal_not_updated_on_transfer.py - Custom Slither detector.

Pattern (Zellic slice_ag Rover, MEDIUM): An ERC-4626 vault maintains a
`principalAssets[user]` / `costBasis[user]` / `entryValue[user]` mapping used
for performance-fee calculations. The contract overrides `_update`,
`_transfer`, or `_beforeTokenTransfer` to run extra hooks, but the override
does NOT move principal from `from` to `to` on direct share transfers. When
Alice transfers shares to Bob, Bob's cost basis remains zero and Bob is
charged performance fees on Alice's unrealized PnL.

Detection strategy:
    1. Find a contract that declares a state-var mapping whose name matches
       (?i)principal|costBasis|entryValue.
    2. That contract overrides `_update`/`_transfer`/`_beforeTokenTransfer`
       (declared locally, not only inherited).
    3. In the override body, NO write occurs to the principal mapping.
    4. If all three conditions hold, flag the override.

@author auditooor wave8
@pattern slice_ag Rover
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
from slither.core.solidity_types import MappingType
from slither.utils.output import Output


_SKIP_KEYWORDS = ("test", "mock", "fixture", "helper", "script", "setup", "deploy")

_PRINCIPAL_RE = re.compile(
    r"principal|costbasis|cost_basis|entryvalue|entry_value|deposit(ed)?assets",
    re.IGNORECASE,
)

_HOOK_NAMES = frozenset({
    "_update",
    "_transfer",
    "_beforeTokenTransfer",
    "_afterTokenTransfer",
})


class Erc4626PrincipalNotUpdatedOnTransfer(AbstractDetector):
    """Detect ERC-4626 transfer hooks that do not migrate principal accounting."""

    ARGUMENT = "erc4626-principal-not-updated-on-transfer"
    HELP = (
        "Transfer hook (_update/_transfer/_beforeTokenTransfer) does not move "
        "principal/costBasis between from and to - performance fees mis-charged"
    )
    IMPACT = DetectorClassification.MEDIUM
    CONFIDENCE = DetectorClassification.MEDIUM

    WIKI = "https://github.com/Vuk97/auditooor/blob/main/reference/bug_patterns_observed.md"
    WIKI_TITLE = "ERC-4626 Principal Not Updated On Share Transfer"
    WIKI_DESCRIPTION = (
        "Vaults that charge performance fees based on a per-user principal/"
        "cost-basis mapping must move that cost basis whenever shares change "
        "hands, not just at deposit/withdraw. When the vault overrides a "
        "transfer hook but forgets to migrate principal, the recipient of a "
        "share transfer inherits zero cost basis and is charged performance "
        "fees on the sender's unrealized PnL. Conversely, the sender's "
        "principal stays put, meaning the same dollar of gain is taxed twice."
    )
    WIKI_EXPLOIT_SCENARIO = """
```solidity
mapping(address => uint256) public principalAssets;

function _update(address from, address to, uint256 shares) internal override {
    super._update(from, to, shares);
    // BUG: no movement of principalAssets
}
```
Alice deposits 1000 assets → `principalAssets[alice] = 1000`. Value doubles.
Alice transfers all shares to Bob. Bob withdraws: the vault sees
`principalAssets[bob] == 0`, treats the full amount as performance gain, and
takes a fat cut - Bob loses funds that weren't his gain to begin with."""
    WIKI_RECOMMENDATION = (
        "In the transfer hook, when both `from` and `to` are non-zero, "
        "transfer a proportional slice of `principalAssets[from]` to "
        "`principalAssets[to]` (proportional to shares/balanceOf(from))."
    )

    def _detect(self) -> list[Output]:
        results: list[Output] = []

        for contract in self.contracts:
            if is_vendored_or_test_contract(contract):
                continue
            if any(k in contract.name.lower() for k in _SKIP_KEYWORDS):
                continue

            # Step 1: find principal/costBasis mapping state vars.
            principal_svs = [
                sv for sv in contract.state_variables
                if isinstance(sv.type, MappingType)
                and _PRINCIPAL_RE.search(sv.name or "")
            ]
            if not principal_svs:
                continue
            principal_set = set(principal_svs)

            # Step 2: find locally-declared hook overrides.
            for function in contract.functions_and_modifiers_declared:
                if function.name not in _HOOK_NAMES:
                    continue
                # Must be an override (not the base declaration itself).
                # Heuristic: contract is NOT the canonical base - if the
                # base were the only declarer we wouldn't be here because
                # functions_and_modifiers_declared returns locally declared
                # only. So presence alone is sufficient.

                # Step 3: check body for writes to any principal mapping.
                writes_principal = False
                for node in function.nodes:
                    for sv in node.state_variables_written:
                        if sv in principal_set:
                            writes_principal = True
                            break
                    if writes_principal:
                        break

                if writes_principal:
                    continue

                info: DETECTOR_INFO = [
                    function,
                    " overrides ",
                    function.name,
                    " on ",
                    contract,
                    " without writing to the principal mapping ",
                    principal_svs[0],
                    " - direct share transfers leave the recipient with zero "
                    "cost basis, causing performance-fee mis-charge.\n",
                ]
                results.append(self.generate_result(info))

        return results
