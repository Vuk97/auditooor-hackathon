"""
redacted-cartel-transferfrom-reads-wrong-allowance-pair — generated from reference/patterns.dsl/redacted-cartel-transferfrom-reads-wrong-allowance-pair.yaml
DO NOT EDIT BY HAND. Regenerate via: python3 tools/pattern-compile.py redacted-cartel-transferfrom-reads-wrong-allowance-pair.yaml
Source: auditooor-R76-immunefi-redacted-cartel-$560k
"""

import sys
from pathlib import Path as _Path
sys.path.insert(0, str(_Path(__file__).resolve().parent.parent))
from _template_utils import is_vendored_or_test_contract, is_leaf_helper
from _predicate_engine import eval_preconditions, eval_function_match

from slither.detectors.abstract_detector import AbstractDetector, DetectorClassification


class RedactedCartelTransferfromReadsWrongAllowancePair(AbstractDetector):
    ARGUMENT = "redacted-cartel-transferfrom-reads-wrong-allowance-pair"
    HELP = "transferFrom reads the allowance of the recipient but decrements the allowance of msg.sender — approvals can be stolen by passing amount=0."
    IMPACT = DetectorClassification.MEDIUM
    CONFIDENCE = DetectorClassification.HIGH
    WIKI = "https://github.com/Vuk97/auditooor/blob/main/reference/patterns.dsl/redacted-cartel-transferfrom-reads-wrong-allowance-pair.yaml"
    WIKI_TITLE = "Custom transferFrom reads allowance[owner][to] and writes allowance[owner][msg.sender]"
    WIKI_DESCRIPTION = "A hand-rolled ERC-20 (e.g. freezable/wrapped variant) has a typo in transferFrom: it computes the new allowance using `allowance[owner][recipient]` (the *recipient*'s allowance) but stores the result into `allowance[owner][msg.sender]`. Anyone calling `transferFrom(owner, victimContract, 0)` copies `victimContract`'s allowance onto their own address. A follow-up transferFrom drains the owner."
    WIKI_EXPLOIT_SCENARIO = "wxBTRFLY's FrozenToken had this exact typo. Any address that had an approved contract could be drained: attacker calls transferFrom(Alice, aliceDapp, 0) — now attacker has Alice's approval. Second call transferFrom(Alice, attacker, aliceBalance) succeeds. $6M at risk, $560k bounty."
    WIKI_RECOMMENDATION = "Never hand-roll ERC-20 accounting — inherit OpenZeppelin's ERC20. If you must, write a property test: `forall owner, spender, other: transferFrom must only decrement allowance[owner][msg.sender], never allowance[owner][other]`. Echidna/Foundry invariant is two lines."

    _PRECONDITIONS = [{'contract.source_matches_regex': '(?i)(allowance|_allowances)'}]
    _MATCH = [{'function.kind': 'external_or_public'}, {'function.name_matches': '(?i)^transferFrom$'}, {'function.body_contains_regex': '(?i)allowance\\s*\\[\\s*\\w+\\s*\\]\\s*\\[\\s*(?:to|recipient|_to|dst)\\s*\\]|_allowances\\s*\\[\\s*\\w+\\s*\\]\\s*\\[\\s*(?:to|recipient|_to|dst)\\s*\\]'}, {'function.reads_msg_sender': True}, {'function.body_contains_regex': '(?i)allowance\\s*\\[\\s*\\w+\\s*\\]\\s*\\[\\s*msg\\.sender\\s*\\]\\s*=|_allowances\\s*\\[\\s*\\w+\\s*\\]\\s*\\[\\s*msg\\.sender\\s*\\]\\s*='}, {'function.not_in_skip_list': True}, {'function.not_source_matches_regex': '(?i)\\b(mock|test|fixture)'}]

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
                info = [f, f" — redacted-cartel-transferfrom-reads-wrong-allowance-pair: pattern matched. See WIKI for details."]
                results.append(self.generate_result(info))
        return results
