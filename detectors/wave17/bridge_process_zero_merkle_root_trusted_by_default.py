"""
bridge-process-zero-merkle-root-trusted-by-default — generated from reference/patterns.dsl/bridge-process-zero-merkle-root-trusted-by-default.yaml
DO NOT EDIT BY HAND. Regenerate via: python3 tools/pattern-compile.py bridge-process-zero-merkle-root-trusted-by-default.yaml
Source: auditooor-R76-rekt-nomad-2022
"""

import sys
from pathlib import Path as _Path
sys.path.insert(0, str(_Path(__file__).resolve().parent.parent))
from _template_utils import is_vendored_or_test_contract, is_leaf_helper
from _predicate_engine import eval_preconditions, eval_function_match

from slither.detectors.abstract_detector import AbstractDetector, DetectorClassification


class BridgeProcessZeroMerkleRootTrustedByDefault(AbstractDetector):
    ARGUMENT = "bridge-process-zero-merkle-root-trusted-by-default"
    HELP = "Bridge message processor trusts a root lookup without rejecting bytes32(0). An initializer or upgrade that leaves the zero-root marked valid causes every default-initialized message to satisfy the proof check."
    IMPACT = DetectorClassification.MEDIUM
    CONFIDENCE = DetectorClassification.HIGH
    WIKI = "https://github.com/Vuk97/auditooor/blob/main/reference/patterns.dsl/bridge-process-zero-merkle-root-trusted-by-default.yaml"
    WIKI_TITLE = "Cross-chain message processor accepts bytes32(0) merkle root as trusted"
    WIKI_DESCRIPTION = "Bridge inbound handlers typically verify that a committed merkle root has been confirmed (e.g. `confirmAt[root] <= block.timestamp`). If the zero root is ever marked confirmed — whether by an initializer bug, a buggy upgrade, or a default-value write — then any message whose root is never set (still bytes32(0)) is treated as already proven and handed to the dispatcher. The Nomad bridge lost ~$190M"
    WIKI_EXPLOIT_SCENARIO = "Attacker copies a legitimate `process(message)` call, edits the recipient/amount, and submits. The message was never proved via `prove()`, so its stored root is bytes32(0). The check `confirmAt[0x0] <= block.timestamp` passes because 0x0 was inadvertently marked trusted. The message is dispatched and the attacker walks away with bridge inventory. Every other attacker front-runs the first exploit b"
    WIKI_RECOMMENDATION = "Explicitly reject the zero root: `require(root != bytes32(0), \"zero root\");` BEFORE looking it up. In the initializer / upgrader, never write a non-zero value into `confirmAt[bytes32(0)]`. Consider making the default value -1 / sentinel rather than 0."

    _PRECONDITIONS = [{'contract.source_matches_regex': '.*'}, 'Function consumes a cross-chain / bridge message and validates it against an on-chain root lookup before dispatching to a handler.']
    _MATCH = [{'function.kind': 'external'}, {'function.name_matches': '(?i)^process$|^dispatchMessage|^handleMessage|^relayMessage|^executeMessage'}, {'function.body_contains_regex': '(?i)confirmAt\\s*\\[|acceptableRoot|committedRoot|messageStatus\\s*\\['}, {'function.body_not_contains_regex': '(?i)require\\s*\\([^;]*!=\\s*0[^;]*root|root\\s*!=\\s*bytes32\\(0\\)|committedRoot\\s*!=\\s*0'}, {'function.not_in_skip_list': True}, {'function.not_leaf_helper': True}, {'function.not_source_matches_regex': '(?i)\\b(mock|test|fixture)'}]

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
                info = [f, f" — bridge-process-zero-merkle-root-trusted-by-default: pattern matched. See WIKI for details."]
                results.append(self.generate_result(info))
        return results
