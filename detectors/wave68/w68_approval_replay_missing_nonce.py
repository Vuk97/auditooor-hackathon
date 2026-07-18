"""
w68-approval-replay-missing-nonce - generated from reference/patterns.dsl/w68-approval-replay-missing-nonce.yaml
DO NOT EDIT BY HAND. Regenerate via: python3 tools/pattern-compile.py w68-approval-replay-missing-nonce.yaml
Source: W6-8 zero-coverage detector batch (auditooor capability lift)
"""

import sys
from pathlib import Path as _Path
sys.path.insert(0, str(_Path(__file__).resolve().parent.parent))
from _template_utils import is_vendored_or_test_contract, is_leaf_helper
from _predicate_engine import eval_preconditions, eval_function_match

from slither.detectors.abstract_detector import AbstractDetector, DetectorClassification


class W68ApprovalReplayMissingNonce(AbstractDetector):
    ARGUMENT = "w68-approval-replay-missing-nonce"
    HELP = "Signed approval, delegation, or preapproval is replayable because the digest or consume path never binds and burns a per-owner nonce, deadline, domain, salt, or target/amount pair."
    IMPACT = DetectorClassification.HIGH
    CONFIDENCE = DetectorClassification.MEDIUM
    WIKI = "https://github.com/Vuk97/auditooor/blob/main/reference/patterns.dsl/w68-approval-replay-missing-nonce.yaml"
    WIKI_TITLE = "Signed approval replayed after intended use"
    WIKI_DESCRIPTION = "A signed approval, permit, delegation, or preapproval is verified but the replay path never binds a per-owner nonce, deadline, domain separator, salt, or consumed marker to the target/amount pair. The same signature or authorization can therefore be replayed to re-grant the approval or delegation."
    WIKI_EXPLOIT_SCENARIO = "Signed approval, delegation, or preapproval is replayable because the digest or consume path never binds and burns a per-owner nonce, deadline, domain, salt, or target/amount pair."
    WIKI_RECOMMENDATION = "Bind the authorization to a per-owner nonce, deadline, chain/domain separator, and target/amount context, then consume the authorization atomically on first use."

    _PRECONDITIONS = [{'contract.source_matches_regex': '(?i)(permit|approv|preapprov|delegat|authori|sign|recover|ecrecover|isValidSignature)'}, {'contract.has_function_matching': '(?i)(permit|approv|preapprov|delegat|authori|sign)'}]
    _MATCH = [{'function.name_matches': '.*(permit|approv).*'}, {'function.not_leaf_helper': True}, {'function.not_in_skip_list': True}, {'function.body_contains_regex': '(?i)(ecrecover|_recover|recover|isValidSignature|signature\\.length\\s*==\\s*0)'}, {'function.writes_state_var_matching_regex': '(?i)(allowance|approval|preapprov|delegat|auth|permission|grant)'}, {'function.body_not_contains_regex': '(?i)(nonce|deadline|expiry|expires|timestamp|domainSeparator|chainid|verifyingContract|salt|used|consum(?:e|ed|ption)|nullifier)'}, {'function.not_source_matches_regex': '(?i)\\b(mock|test|fixture)'}]

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
                info = [f, f" - w68-approval-replay-missing-nonce: pattern matched. See WIKI for details."]
                results.append(self.generate_result(info))
        return results
