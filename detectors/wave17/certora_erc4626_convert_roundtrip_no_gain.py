"""
certora-erc4626-convert-roundtrip-no-gain — generated from reference/patterns.dsl/certora-erc4626-convert-roundtrip-no-gain.yaml
DO NOT EDIT BY HAND. Regenerate via: python3 tools/pattern-compile.py certora-erc4626-convert-roundtrip-no-gain.yaml
Source: certora-examples/ERC4626/roundtripNoGain
"""

import sys
from pathlib import Path as _Path
sys.path.insert(0, str(_Path(__file__).resolve().parent.parent))
from _template_utils import is_vendored_or_test_contract, is_leaf_helper
from _predicate_engine import eval_preconditions, eval_function_match

from slither.detectors.abstract_detector import AbstractDetector, DetectorClassification


class CertoraErc4626ConvertRoundtripNoGain(AbstractDetector):
    ARGUMENT = "certora-erc4626-convert-roundtrip-no-gain"
    HELP = "ERC-4626 conversion uses `mulDiv` without an explicit rounding direction — Certora `roundtripNoGain` invariant may fail; free-mint / free-burn possible."
    IMPACT = DetectorClassification.HIGH
    CONFIDENCE = DetectorClassification.MEDIUM
    WIKI = "https://github.com/Vuk97/auditooor/blob/main/reference/patterns.dsl/certora-erc4626-convert-roundtrip-no-gain.yaml"
    WIKI_TITLE = "ERC-4626 convert* uses mulDiv without explicit rounding direction"
    WIKI_DESCRIPTION = "Certora's ERC-4626 rule-set enforces rounding conventions: `convertToShares` (on deposit), `previewDeposit`, and `previewMint` round DOWN in favor of the vault; `convertToAssets` (on redeem) and `previewWithdraw`, `previewRedeem` also round DOWN (shares up in favor of vault on withdraw). Using a single `mulDiv` without `Rounding.Down` explicit lets the compiler default (which rounds towards zero f"
    WIKI_EXPLOIT_SCENARIO = "Vault defines `convertToShares(a) = a * totalSupply / totalAssets` (no explicit rounding). For a vault with totalAssets=3, totalSupply=2, depositing 2 gives 2*2/3 = 1 share. Redeeming 1 share gives 1*3/2 = 1 asset. User lost 1 wei — OK. But reversed: convertToShares rounds down, convertToAssets rounds up by changing formula order → user deposits 2, gets 1 share, redeems 1 share, gets 2 assets. Amo"
    WIKI_RECOMMENDATION = "Use OpenZeppelin's `Math.mulDiv(a, b, c, Rounding.Floor|Ceil)` or Solmate's `mulDivDown` / `mulDivUp` with a documented direction on every conversion path. Prove the Certora `roundtripNoGain` rule: for all (a, block), `redeem(deposit(a)) <= a`."

    _PRECONDITIONS = [{'contract.source_matches_regex': '.*'}, {'contract.has_function_matching': '(?i)^(convertToShares|convertToAssets|previewDeposit|previewRedeem)$'}]
    _MATCH = [{'function.kind': 'external_or_public'}, {'function.name_matches': '(?i)^(convertToShares|convertToAssets|previewDeposit|previewRedeem|previewMint|previewWithdraw)$'}, {'function.body_contains_regex': '(?i)(mulDiv|muldiv|_mulDiv)'}, {'function.body_not_contains_regex': '(?i)(Rounding\\.Down|Rounding\\.Up|Math\\.Rounding|mulDivDown|mulDivUp|_mulDivDown|_mulDivUp|roundUp|floor|ceil)'}, {'function.not_in_skip_list': True}, {'function.not_leaf_helper': True}, {'function.not_source_matches_regex': '(?i)\\b(mock|test|fixture)'}]

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
                info = [f, f" — certora-erc4626-convert-roundtrip-no-gain: pattern matched. See WIKI for details."]
                results.append(self.generate_result(info))
        return results
