"""
consensys-erc2771-trusted-forwarder-length-check-missing — generated from reference/patterns.dsl/consensys-erc2771-trusted-forwarder-length-check-missing.yaml
DO NOT EDIT BY HAND. Regenerate via: python3 tools/pattern-compile.py consensys-erc2771-trusted-forwarder-length-check-missing.yaml
Source: auditooor-R75-consensys-erc2771-HIGH
"""

import sys
from pathlib import Path as _Path
sys.path.insert(0, str(_Path(__file__).resolve().parent.parent))
from _template_utils import is_vendored_or_test_contract, is_leaf_helper
from _predicate_engine import eval_preconditions, eval_function_match

from slither.detectors.abstract_detector import AbstractDetector, DetectorClassification


class ConsensysErc2771TrustedForwarderLengthCheckMissing(AbstractDetector):
    ARGUMENT = "consensys-erc2771-trusted-forwarder-length-check-missing"
    HELP = "ERC-2771 _msgSender slices last 20 bytes of calldata without checking calldata length >= 20. When the trusted forwarder is NOT the caller AND calldata is shorter than 20 bytes, the slice returns zero-extended garbage that a well-placed direct call can steer."
    IMPACT = DetectorClassification.HIGH
    CONFIDENCE = DetectorClassification.HIGH
    WIKI = "https://github.com/Vuk97/auditooor/blob/main/reference/patterns.dsl/consensys-erc2771-trusted-forwarder-length-check-missing.yaml"
    WIKI_TITLE = "ERC-2771 context reads last 20 bytes of calldata without length guard"
    WIKI_DESCRIPTION = "`ERC2771Context._msgSender()` inspects whether `isTrustedForwarder(msg.sender)` and if so returns `msg.data[msg.data.length - 20:]`. If the trusted-forwarder branch is taken but the calldata is shorter than 20 bytes (e.g. the forwarder is compromised and forwards a bare selector, or a proxy path leads to a <20-byte dispatch), the slice underflows. Older versions before OZ 4.8 used `sub(calldatasiz"
    WIKI_EXPLOIT_SCENARIO = "A trusted forwarder with a bug accepts and forwards a 4-byte payload (selector only), omitting the appended sender. The target's _msgSender() does `msg.data[length-20..]` — with length=4, this wraps via underflow to a large offset, reads uninitialised calldata as address bytes, and returns a spoofed sender that may match a privileged address depending on how the proxy dispatcher left free memory. "
    WIKI_RECOMMENDATION = "Guard every calldata-slice read: `if (msg.data.length >= _contextSuffixLength())`. OZ 4.9+ uses `_contextSuffixLength()` returning 20 with the check. Any custom ERC2771Context must port this guard. Additionally: restrict `isTrustedForwarder` to a set of audited forwarders, and prefer ERC-4337 / SCA "

    _PRECONDITIONS = [{'contract.source_matches_regex': '.*'}, {'contract.inherits': 'ERC2771Context|ERC2771ContextUpgradeable'}, {'contract.has_function_matching': '_msgSender|_msgData'}]
    _MATCH = [{'function.kind': 'internal_or_public'}, {'function.name_matches': '^(_msgSender|_msgData)$'}, {'function.body_contains_regex': 'msg\\.data\\[msg\\.data\\.length\\s*-\\s*20|calldataload.*sub\\(calldatasize'}, {'function.body_not_contains_regex': 'msg\\.data\\.length\\s*>=\\s*20|_contextSuffixLength'}, {'function.not_in_skip_list': True}, {'function.not_leaf_helper': True}, {'function.not_source_matches_regex': '(?i)\\b(mock|test|fixture)'}]

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
                info = [f, f" — consensys-erc2771-trusted-forwarder-length-check-missing: pattern matched. See WIKI for details."]
                results.append(self.generate_result(info))
        return results
