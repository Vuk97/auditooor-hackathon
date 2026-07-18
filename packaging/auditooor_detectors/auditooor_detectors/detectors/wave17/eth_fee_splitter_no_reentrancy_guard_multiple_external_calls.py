"""
eth-fee-splitter-no-reentrancy-guard-multiple-external-calls — generated from reference/patterns.dsl/eth-fee-splitter-no-reentrancy-guard-multiple-external-calls.yaml
DO NOT EDIT BY HAND. Regenerate via: python3 tools/pattern-compile.py eth-fee-splitter-no-reentrancy-guard-multiple-external-calls.yaml
Source: auditooor-R108-kiln-v1-pr263-fee-dispatcher
"""

import sys
from pathlib import Path as _Path
sys.path.insert(0, str(_Path(__file__).resolve().parent.parent))
from _template_utils import is_vendored_or_test_contract, is_leaf_helper
from _predicate_engine import eval_preconditions, eval_function_match

from slither.detectors.abstract_detector import AbstractDetector, DetectorClassification


class EthFeeSplitterNoReentrancyGuardMultipleExternalCalls(AbstractDetector):
    ARGUMENT = "eth-fee-splitter-no-reentrancy-guard-multiple-external-calls"
    HELP = "Payable fee-distribution function reads address(this).balance / msg.value, then performs 2+ sequential `.call{value:}` hops to externally-controlled recipients (withdrawer / treasury / operator getters), without a `nonReentrant` modifier or equivalent local lock. Each call hands control to an untrus"
    IMPACT = DetectorClassification.HIGH
    CONFIDENCE = DetectorClassification.MEDIUM
    WIKI = "https://github.com/Vuk97/auditooor/blob/main/reference/patterns.dsl/eth-fee-splitter-no-reentrancy-guard-multiple-external-calls.yaml"
    WIKI_TITLE = "Payable fee dispatcher with multiple sequential .call{value:} hops and no reentrancy guard"
    WIKI_DESCRIPTION = "ETH fee splitters are commonly written as `function dispatch() external payable { uint balance = address(this).balance; ... withdrawer.call{value: x}(...); treasury.call{value: y}(...); operator.call{value: z}(...); }`. Without a `nonReentrant` modifier (or equivalent guard) the sequence is fragile: every `.call{value:}` hands control to an externally-controlled address whose receive() / fallback("
    WIKI_EXPLOIT_SCENARIO = "Lido-style ETH fee splitter has function `payout(bytes32 _validator) external payable { uint bal = address(this).balance; uint feeShare = bal * fee / BPS; (bool ok,) = withdrawerOf[_validator].call{value: bal - feeShare}(''); ... (ok,) = treasury.call{value: feeShare * 80 / 100}(''); ... (ok,) = operatorOf[_validator].call{value: feeShare * 20 / 100}(''); }`. A v2 patch ships that records a `lifet"
    WIKI_RECOMMENDATION = "Add OpenZeppelin's `nonReentrant` modifier (or a local boolean lock with `require(!_locked); _locked = true; ...; _locked = false;`). For maximum safety in multi-recipient distribution, accumulate per-recipient owed amounts in a mapping FIRST, then have recipients pull via a separate `claim(recipien"

    _PRECONDITIONS = [{'contract.source_matches_regex': 'dispatch|distribute|payout|skim|splitFees|sweepFees|withdrawAndSplit|FeeDispatcher|RewardDispatcher|FeeSplitter'}]
    _MATCH = [{'function.kind': 'external_or_public'}, {'function.is_payable': True}, {'function.name_matches': '^(dispatch|distribute|distributeFees|payout|payoutAll|splitFees|skim|sweep|sweepFees|withdrawAndDistribute|forwardFees|push|claim)$'}, {'function.body_contains_regex': 'address\\s*\\(\\s*this\\s*\\)\\s*\\.\\s*balance|msg\\.value'}, {'function.body_contains_regex': '\\.call\\s*\\{\\s*value\\s*:[^}]*\\}\\s*\\([^)]*\\)[\\s\\S]{0,800}\\.call\\s*\\{\\s*value\\s*:[^}]*\\}\\s*\\('}, {'function.body_not_contains_regex': 'nonReentrant|ReentrancyGuard|_locked\\s*=\\s*true|require\\s*\\(\\s*!\\s*_?[Ll]ocked'}, {'function.body_contains_regex': '\\.\\s*get[A-Z][a-zA-Z]*\\s*\\(|\\[\\s*[a-zA-Z_]+\\s*\\]|address\\s*\\(\\s*[a-zA-Z]'}, {'function.not_in_skip_list': True}, {'function.not_leaf_helper': True}, {'function.not_source_matches_regex': '(?i)\\b(mock|test|fixture)'}]

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
                info = [f, f" — eth-fee-splitter-no-reentrancy-guard-multiple-external-calls: pattern matched. See WIKI for details."]
                results.append(self.generate_result(info))
        return results
