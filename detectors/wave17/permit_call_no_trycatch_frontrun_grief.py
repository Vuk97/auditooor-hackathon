"""
permit-call-no-trycatch-frontrun-grief — generated from reference/patterns.dsl/permit-call-no-trycatch-frontrun-grief.yaml
DO NOT EDIT BY HAND. Regenerate via: python3 tools/pattern-compile.py permit-call-no-trycatch-frontrun-grief.yaml
Source: solodit-cluster/permit-frontrun-grief-generalizer
"""

import sys
from pathlib import Path as _Path
sys.path.insert(0, str(_Path(__file__).resolve().parent.parent))
from _template_utils import is_vendored_or_test_contract, is_leaf_helper
from _predicate_engine import eval_preconditions, eval_function_match

from slither.detectors.abstract_detector import AbstractDetector, DetectorClassification


class PermitCallNoTrycatchFrontrunGrief(AbstractDetector):
    ARGUMENT = "permit-call-no-trycatch-frontrun-grief"
    HELP = "External function forwards a user-supplied EIP-2612 permit signature to token.permit() with no try/catch wrapper and no allowance() pre-check fall-through. A front-runner can replay the signed permit first, consuming the one-shot nonce; the victim's combined permit+action tx then reverts (grief DoS)"
    IMPACT = DetectorClassification.MEDIUM
    CONFIDENCE = DetectorClassification.MEDIUM
    WIKI = "https://github.com/Vuk97/auditooor/blob/main/reference/patterns.dsl/permit-call-no-trycatch-frontrun-grief.yaml"
    WIKI_TITLE = "permit() forwarded without try/catch — front-run grief DoS (transaction-ordering race)"
    WIKI_DESCRIPTION = "ERC-2612 permit consumes a one-shot nonce. A contract that wraps a deposit/withdraw/swap around token.permit() without a try/catch wrapper (and without an allowance() pre-check that skips permit when the allowance already covers the amount) is vulnerable to a mempool front-run: any observer extracts the permit args, calls token.permit() standalone first, and the victim's combined transaction rever"
    WIKI_EXPLOIT_SCENARIO = "Victim broadcasts depositWithPermit(amount, deadline, v, r, s). An MEV bot copies the permit args from the mempool and submits token.permit(victim, vault, amount, deadline, v, r, s) at higher gas. The bot's permit lands first and consumes the victim's nonce. The victim's transaction then reverts at the token.permit() call (invalid/used signature), the victim pays gas with no deposit, and the bot r"
    WIKI_RECOMMENDATION = "Wrap the permit call in try/catch — `try token.permit(owner, spender, value, deadline, v, r, s) {} catch {}` — so a front-run nonce-consumption is swallowed and the subsequent transferFrom still enforces the (now-granted) allowance. Alternatively, check `token.allowance(owner, spender) >= amount` fi"

    _PRECONDITIONS = [{'contract.source_matches_regex': '\\.permit\\s*\\('}]
    _MATCH = [{'function.kind': 'external_or_public'}, {'function.body_contains_regex': '\\.permit\\s*\\('}, {'function.body_not_contains_regex': '(?s)try\\s+[^;{]*\\.permit\\s*\\(|catch\\s*(\\(|\\{)'}, {'function.body_not_contains_regex': '\\.allowance\\s*\\(|Permit2|SafePermit|safePermit\\s*\\('}, {'function.not_leaf_helper': True}, {'function.not_source_matches_regex': '(?i)\\b(mock|test|fixture)\\b'}, {'function.not_source_matches_regex': '(?i)(view\\s+returns|pure\\s+returns|internal\\s+view|internal\\s+pure)'}]

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
                info = [f, f" — permit-call-no-trycatch-frontrun-grief: pattern matched. See WIKI for details."]
                results.append(self.generate_result(info))
        return results
