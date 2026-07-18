"""
wrap-mint-before-vault-transfer-callback-window — generated from reference/patterns.dsl/wrap-mint-before-vault-transfer-callback-window.yaml
DO NOT EDIT BY HAND. Regenerate via: python3 tools/pattern-compile.py wrap-mint-before-vault-transfer-callback-window.yaml
Source: auditooor-r112-polymarket-source-mine-CollateralToken.wrap
"""

import sys
from pathlib import Path as _Path
sys.path.insert(0, str(_Path(__file__).resolve().parent.parent))
from _template_utils import is_vendored_or_test_contract, is_leaf_helper
from _predicate_engine import eval_preconditions, eval_function_match

from slither.detectors.abstract_detector import AbstractDetector, DetectorClassification


class WrapMintBeforeVaultTransferCallbackWindow(AbstractDetector):
    ARGUMENT = "wrap-mint-before-vault-transfer-callback-window"
    HELP = "Wrapper function _mints shares, then invokes a user-controlled callback, then transfers the backing asset to the vault — a CEI violation that exposes a re-entrant unbacked-state window."
    IMPACT = DetectorClassification.MEDIUM
    CONFIDENCE = DetectorClassification.MEDIUM
    WIKI = "https://github.com/Vuk97/auditooor/blob/main/reference/patterns.dsl/wrap-mint-before-vault-transfer-callback-window.yaml"
    WIKI_TITLE = "Wrapper mints shares before backing-asset transfer with mid-flow callback (CEI violation)"
    WIKI_DESCRIPTION = "Generic ERC20/ERC4626/wrapped-collateral CEI bug. The wrap function follows the dangerous ordering: (1) `_mint(_to, amount)` — the recipient now holds wrapped tokens; (2) call an external `wrapCallback`/`onWrap`/`tokenReceived` hook on a caller-supplied receiver; (3) `safeTransfer` the backing asset to the vault/reserve. Between steps 1 and 3 the contract is in an inconsistent state: total wrapped"
    WIKI_EXPLOIT_SCENARIO = "A WRAPPER_ROLE-holding adapter forwards an end-user wrap via `CollateralToken.wrap(asset, user, amount, callbackReceiver=AttackerContract, data)`. Inside the wrap, `_mint` issues `amount` pUSD to the user — but the asset has not yet reached the vault. The adapter's `wrapCallback` runs on AttackerContract, which can: (a) read totalSupply/totalAssets and infer the inflated supply, (b) call any view "
    WIKI_RECOMMENDATION = "Reorder the wrap to perform the asset transfer BEFORE minting (`safeTransfer(VAULT, amount)` first, then `_mint(_to, amount)`), and execute any callback AFTER mint, OR add `nonReentrant` AND a vault-balance-delta post-check (`require(vault.balanceOf(asset) >= preBalance + amount)`) to ensure the ass"

    _PRECONDITIONS = [{'contract.source_matches_regex': '(?i)function\\s+\\w*[Ww]rap\\w*\\s*\\(|wrapCallback|wrap\\s*\\(\\s*address|onWrap|onCollateralWrapped|tokenReceived'}]
    _MATCH = [{'function.kind': 'external_or_public'}, {'function.name_matches': '(?i)^wrap$|^_wrap$|wrapCollateral|wrapTokens|wrapAsset|wrapAndDeposit|wrapWithCallback'}, {'function.body_contains_regex': '(?i)_mint\\s*\\([^)]*\\)\\s*;[\\s\\S]*?\\.\\s*\\w*[Cc]allback\\s*\\([^)]*\\)[\\s\\S]*?(safeTransfer\\s*\\(|transfer\\s*\\(|safeTransferFrom\\s*\\(|deposit\\s*\\()'}, {'function.body_not_contains_regex': '(?i)nonReentrant|noReentrant|ReentrancyGuard|_lock|reentrancyLock|_status\\s*=\\s*\\d+|safeTransfer\\s*\\([^)]*\\)\\s*;\\s*[\\s\\S]*?\\.\\s*\\w*[Cc]allback[\\s\\S]*?_mint|balanceOf\\s*\\(\\s*VAULT\\s*\\)\\s*[-+>=]'}, {'function.not_in_skip_list': True}, {'function.not_leaf_helper': True}, {'function.not_source_matches_regex': '(?i)\\b(mock|test|fixture)'}]

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
                info = [f, f" — wrap-mint-before-vault-transfer-callback-window: pattern matched. See WIKI for details."]
                results.append(self.generate_result(info))
        return results
