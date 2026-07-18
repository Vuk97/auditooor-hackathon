"""
no-admin-sweep-for-stuck-erc20 — generated from reference/patterns.dsl/no-admin-sweep-for-stuck-erc20.yaml
DO NOT EDIT BY HAND. Regenerate via: python3 tools/pattern-compile.py no-admin-sweep-for-stuck-erc20.yaml
Source: auditooor-R83-polymarket-drafts-6-and-8
"""

import sys
from pathlib import Path as _Path
sys.path.insert(0, str(_Path(__file__).resolve().parent.parent))
from _template_utils import is_vendored_or_test_contract, is_leaf_helper
from _predicate_engine import eval_preconditions, eval_function_match

from slither.detectors.abstract_detector import AbstractDetector, DetectorClassification


class NoAdminSweepForStuckErc20(AbstractDetector):
    ARGUMENT = "no-admin-sweep-for-stuck-erc20"
    HELP = "Token-wrapper / collateral-holder contract has a user-facing wrap/unwrap/redeem entry-point that custodies an ERC20 underlying, but exposes NO admin sweep/rescue/recoverERC20 function. Any token mistakenly sent to the contract address — or any underlying donated outside the wrap path — is permanentl"
    IMPACT = DetectorClassification.LOW
    CONFIDENCE = DetectorClassification.MEDIUM
    WIKI = "https://github.com/Vuk97/auditooor/blob/main/reference/patterns.dsl/no-admin-sweep-for-stuck-erc20.yaml"
    WIKI_TITLE = "Token wrapper / collateral holder lacks admin sweep for stuck ERC20s"
    WIKI_DESCRIPTION = "A user-facing wrapper contract (CollateralToken / WrappedCollateral / CTF adapter / vault) exposes wrap/unwrap/redeem/release endpoints that move the protocol's underlying ERC20 in and out of the contract's own address. The contract custodies the underlying balance for the duration of the wrap-or-unwrap, but ships without any admin recovery function (no sweep / rescue / recoverERC20 / emergencyWit"
    WIKI_EXPLOIT_SCENARIO = "Polymarket `CollateralToken` (`unwrap` requires WRAPPER_ROLE; burns `_amount` pUSD from `address(this)`). Alice intends to send 1,000 pUSD to `NegRiskAdapter` for a wrap, but the UI auto-completes to the `CollateralToken` address. The 1,000 pUSD lands on the wrapper's own balance. No `sweep(address token, address to, uint256 amount)` function exists. No role can call `_burn(address(this), amount)`"
    WIKI_RECOMMENDATION = "Add an admin-gated rescue function:\n\n```solidity\nfunction sweep(address token, address to, uint256 amount) external onlyOwner {\n    require(to != address(0), \"zero recipient\");\n    SafeERC20.safeTransfer(IERC20(token), to, amount);\n    emit Sweep(token, to, amount);\n}\n```\n\nOptionally com"

    _PRECONDITIONS = [{'contract.source_matches_regex': '(?i)contract\\s+\\w*(Collateral|Wrap|CTF|Bridge|Vault|Pool|Adapter|Token)\\w*\\s'}, {'contract.has_function_body_matching': '(IERC20|ERC20|SafeERC20|safeTransfer|safeTransferFrom)\\s*[\\(\\.]'}, {'contract.has_function_matching': '^(unwrap|wrap|redeem|release|withdraw|burn|mint|convert)$'}, {'contract.has_no_function_body_matching': 'function\\s+(sweep|sweepTokens|rescue|rescueTokens|rescueERC20|recoverERC20|recoverTokens|emergencyWithdraw|adminWithdraw|withdrawStuck|skim|salvage)\\s*\\('}, {'contract.source_not_contains_regex': '(?i)abstract\\s+contract\\s+(Proxy|UUPSUpgradeable|Initializable|ERC1967Upgrade|BeaconProxy)\\b'}]
    _MATCH = [{'function.kind': 'external_or_public'}, {'function.name_matches': '^(unwrap|wrap|redeem|release|withdraw)$'}, {'function.body_contains_regex': '(safeTransfer|safeTransferFrom|\\.transfer\\s*\\(|\\.transferFrom\\s*\\()'}, {'function.not_in_skip_list': True}, {'function.not_leaf_helper': True}, {'function.body_not_contains_regex': '(?i)mock|test|fixture'}, {'function.not_source_matches_regex': '(?i)\\b(mock|test|fixture)'}]

    _INCLUDE_LEAF_HELPERS = False
    _INVERSE_CEI = False

    def _detect(self):
        results = []
        for c in self.contracts:
            if is_vendored_or_test_contract(c):
                continue
            if not eval_preconditions(c, self._PRECONDITIONS):
                continue
            for f in c.functions_and_modifiers_declared:
                if not self._INCLUDE_LEAF_HELPERS and is_leaf_helper(f):
                    continue
                if not eval_function_match(f, self._MATCH):
                    continue
                info = [f, f" — no-admin-sweep-for-stuck-erc20: pattern matched. See WIKI for details."]
                results.append(self.generate_result(info))
        return results
