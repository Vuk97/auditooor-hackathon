"""
liquidation-signature-missing-deadline-check — generated from reference/patterns.dsl/liquidation-signature-missing-deadline-check.yaml
DO NOT EDIT BY HAND. Regenerate via: python3 tools/pattern-compile.py liquidation-signature-missing-deadline-check.yaml
Source: W6-8 Worker BH liquidation recall lift; stale liquidation authorization sibling shape
"""

import sys
from pathlib import Path as _Path
sys.path.insert(0, str(_Path(__file__).resolve().parent.parent))
from _template_utils import is_vendored_or_test_contract, is_leaf_helper
from _predicate_engine import eval_preconditions, eval_function_match

from slither.detectors.abstract_detector import AbstractDetector, DetectorClassification


class LiquidationSignatureMissingDeadlineCheck(AbstractDetector):
    ARGUMENT = "liquidation-signature-missing-deadline-check"
    HELP = "Liquidation path verifies a signature but omits deadline/expiry freshness enforcement, enabling stale liquidation authorization replay."
    IMPACT = DetectorClassification.HIGH
    CONFIDENCE = DetectorClassification.MEDIUM
    WIKI = "https://github.com/Vuk97/auditooor/blob/main/reference/patterns.dsl/liquidation-signature-missing-deadline-check.yaml"
    WIKI_TITLE = "Liquidation signature missing deadline check"
    WIKI_DESCRIPTION = "Liquidation authorization that relies on off-chain signatures must enforce freshness on-chain. If the function recovers a signer but never checks `block.timestamp <= deadline` (or equivalent expiry bound), stale liquidation authorizations remain executable long after market conditions changed."
    WIKI_EXPLOIT_SCENARIO = "A liquidator obtains an oracle-signed liquidation authorization while a borrower is unhealthy. The borrower later recovers health before the signed deadline would normally expire, but the contract never checks deadline at all. The liquidator can still execute with the old signature and seize collateral at stale conditions."
    WIKI_RECOMMENDATION = "Include a signed `deadline`/`expiry` field in the message digest and enforce `require(block.timestamp <= deadline, 'expired')` before executing liquidation."

    _PRECONDITIONS = [{'contract.source_matches_regex': '(?i)(liquidat|forceClose|ecrecover|ECDSA\\.recover|SignatureChecker)'}]
    _MATCH = [{'function.kind': 'external_or_public'}, {'function.name_matches': '(?i)(liquidat|forceClose|seize|closePosition)'}, {'function.body_contains_regex': '(?i)(ecrecover|ECDSA\\.recover|SignatureChecker)'}, {'function.body_contains_regex': '(?i)(deadline|expiry|validUntil|expiresAt)'}, {'function.body_not_contains_regex': '(?is)(block\\.timestamp\\s*(?:<=|<)\\s*[^;]*(deadline|expiry|validUntil|expiresAt)|(?:deadline|expiry|validUntil|expiresAt)\\s*(?:>=|>)\\s*block\\.timestamp)'}, {'function.not_in_skip_list': True}, {'function.not_leaf_helper': True}, {'function.not_source_matches_regex': '(?i)\\b(mock|test|fixture)\\b'}]

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
                info = [f, f" — liquidation-signature-missing-deadline-check: pattern matched. See WIKI for details."]
                results.append(self.generate_result(info))
        return results
