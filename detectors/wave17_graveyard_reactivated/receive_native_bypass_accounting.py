"""
receive_native_bypass_accounting.py - Custom Slither detector.

Pattern (Kinetiq slice_ac HIGH - StakingManager-HYPE-Receive-Exchange-Rate-
Inflate): A vault-like / liquid-staking manager contract declares a
`receive()` or `fallback() external payable` function that silently accepts
native token. Because the vault computes its exchange rate as
`totalAssets / totalSupply` (where `totalAssets` usually reads
`address(this).balance`), any native-token donation directly inflates the
rate, breaking proportional redemptions and enabling grief against
`confirmWithdrawal`/`preview*` callers.

Detection strategy:
    1. Find contracts that (a) have a state-var whose name matches
       `totalAssets|totalSupply|exchangeRate|sharePrice|pricePerShare` AND
       (b) implement a share-minting path - approximated by presence of a
       function whose name matches `deposit|mint|stake`.
    2. Inspect receive() / fallback(). If payable AND its body is empty or
       does NOT call any internal accounting helper (no InternalCall to a
       function whose name matches `_mint|_deposit|_accrue|_update|_account|
       _credit`), flag it.

Distinction from existing detectors:
    - `exchange_rate_inflation_floor` (wave6): share-price inflation via
      first-depositor donation into an empty vault.
    - `erc4626_principal_not_updated_on_transfer` (wave8): principal accounting.
    - `balance_conflation_reward_equals_pool_token` (wave9): reward/reserve
      conflation in AMMs.
This detector targets the *receive-level* donation vector: native token sent
directly to a staking manager without going through deposit().

@author auditooor wave11
@pattern slice_ac Kinetiq - StakingManager-HYPE-Receive-Exchange-Rate-Inflate
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
from slither.slithir.operations import InternalCall
from slither.utils.output import Output


_SKIP_KEYWORDS = ("test", "mock", "fixture", "helper", "script", "setup", "deploy")

_RATE_RE = re.compile(
    r"totalassets|totalsupply|exchangerate|shareprice|priceper|totalpooled",
    re.IGNORECASE,
)
_MINT_RE = re.compile(r"^(deposit|mint|stake|submit)", re.IGNORECASE)
_ACCOUNT_RE = re.compile(
    r"^_?(mint|deposit|accrue|update|account|credit|stake|record)",
    re.IGNORECASE,
)


def _has_rate_state(contract) -> bool:
    for sv in contract.state_variables:
        if _RATE_RE.search(sv.name or ""):
            return True
    return False


def _has_share_minting(contract) -> bool:
    for f in contract.functions_and_modifiers_declared:
        if f.is_constructor:
            continue
        if _MINT_RE.search(f.name or ""):
            return True
    return False


def _receive_or_fallback(contract):
    for f in contract.functions_and_modifiers_declared:
        if f.is_receive or f.is_fallback:
            yield f


def _body_calls_accounting(function) -> bool:
    for node in function.nodes:
        for ir in node.irs:
            if not isinstance(ir, InternalCall):
                continue
            callee = ir.function
            if callee is None:
                continue
            cname = getattr(callee, "name", "") or ""
            if _ACCOUNT_RE.match(cname):
                return True
    return False


class ReceiveNativeBypassAccounting(AbstractDetector):
    """Flag payable receive/fallback on a share-minting vault that skips accounting."""

    ARGUMENT = "receive-native-bypass-accounting"
    HELP = (
        "Vault/staking manager receive()/fallback() accepts native token "
        "without routing through accounting - donations inflate share price"
    )
    IMPACT = DetectorClassification.HIGH
    CONFIDENCE = DetectorClassification.MEDIUM

    WIKI = "https://github.com/Vuk97/auditooor/blob/main/reference/bug_patterns_observed.md"
    WIKI_TITLE = "Receive Native Bypasses Share Accounting"
    WIKI_DESCRIPTION = (
        "A share-minting contract (liquid-staking manager, ERC-4626-like "
        "native vault) declares a `receive()` or `fallback() external "
        "payable` whose body is empty or does not call any accounting "
        "helper. Native tokens arriving this way raise "
        "`address(this).balance` (and hence the exchange rate) without "
        "minting matching shares, so every subsequent depositor pays an "
        "inflated price and early redeemers are diluted. Reported in "
        "Kinetiq StakingManager."
    )
    WIKI_EXPLOIT_SCENARIO = """
```solidity
contract StakingManager {
    uint256 public totalAssets;
    uint256 public totalSupply;

    function deposit() external payable { /* mint shares */ }

    // BUG: payable receive with no accounting
    receive() external payable {}
}
```
Attacker sends 1 HYPE via plain transfer. `address(this).balance` jumps, but
`totalSupply` is unchanged, so every previewed share-price is off. "
The attacker can sandwich a legitimate `confirmWithdrawal` to steal excess."""
    WIKI_RECOMMENDATION = (
        "Either revert in `receive()` / `fallback()` (explicit deposit-only "
        "entry), or route the incoming value through the same internal "
        "`_deposit`/`_mint` path that tracks total shares and assets."
    )

    def _detect(self) -> list[Output]:
        results: list[Output] = []

        for contract in self.contracts:
            if is_vendored_or_test_contract(contract):
                continue
            if any(k in contract.name.lower() for k in _SKIP_KEYWORDS):
                continue
            if not _has_rate_state(contract):
                continue
            if not _has_share_minting(contract):
                continue

            for f in _receive_or_fallback(contract):
                if not f.payable:
                    continue
                if _body_calls_accounting(f):
                    continue
                info: DETECTOR_INFO = [
                    f,
                    " accepts native token without routing through share "
                    "accounting - direct sends inflate the exchange rate.\n",
                ]
                results.append(self.generate_result(info))

        return results
