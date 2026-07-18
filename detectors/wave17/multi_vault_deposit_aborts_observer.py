"""
multi-vault-deposit-aborts-observer — generated from reference/patterns.dsl/multi-vault-deposit-aborts-observer.yaml
DO NOT EDIT BY HAND. Regenerate via: python3 tools/pattern-compile.py multi-vault-deposit-aborts-observer.yaml
Source: auditooor-R75-code4rena-2024-06-thorchain-27
"""

import sys
from pathlib import Path as _Path
sys.path.insert(0, str(_Path(__file__).resolve().parent.parent))
from _template_utils import is_vendored_or_test_contract, is_leaf_helper
from _predicate_engine import eval_preconditions, eval_function_match

from slither.detectors.abstract_detector import AbstractDetector, DetectorClassification


class MultiVaultDepositAbortsObserver(AbstractDetector):
    ARGUMENT = "multi-vault-deposit-aborts-observer"
    HELP = "Log parser aborts the entire tx when a second deposit event has a different destination — batched composability deposits get orphaned."
    IMPACT = DetectorClassification.HIGH
    CONFIDENCE = DetectorClassification.MEDIUM
    WIKI = "https://github.com/Vuk97/auditooor/blob/main/reference/patterns.dsl/multi-vault-deposit-aborts-observer.yaml"
    WIKI_TITLE = "Log parser rejects multi-destination deposits, orphaning funds on batched calls"
    WIKI_DESCRIPTION = "`SmartContractLogParser.GetTxInItem` loops a tx's logs. On the second `Deposit` event, it checks `txInItem.To != depositEvt.To.String()` and `return false, errors.New(\"multiple events ... different to addresses\")`. This abandons *all* events including the first one that parsed successfully. When a composability dApp makes four deposits to multiple vaults in one tx, none of them get posted to THO"
    WIKI_EXPLOIT_SCENARIO = "Aggregator dApp calls router.depositWithExpiry(vault1, USDC), router.depositWithExpiry(vault2, USDC), router.depositWithExpiry(vault2, USDT) in one tx. Log parser reads event 1 OK, event 2 has different `to`, aborts. Observer posts nothing to THORChain. $1M of deposits is trapped."
    WIKI_RECOMMENDATION = "Process each event independently; accumulate a list of TxInItems rather than aggregating into one. If the protocol's invariant is 'one TxIn per tx', emit a distinct event per deposit and loop: one TxInItem per event. Add an on-chain multi-deposit test."

    _PRECONDITIONS = [{'contract.source_matches_regex': '.*'}]
    _MATCH = [{'function.kind': 'any'}, {'function.body_contains_regex': '(?i)for\\s+_,\\s*item\\s*:=\\s*range\\s+logs|for\\s*\\(\\s*Event\\s+e\\s*:\\s*events\\s*\\)|for\\s+log\\s+of\\s+receipt\\.logs'}, {'function.body_contains_regex': '(?i)(different\\s+to\\s+addresses|multiple\\s+events|to\\s+mismatch|aggregate\\s+mismatch)'}, {'function.body_contains_regex': '(?i)return\\s+false,\\s+fmt\\.Errorf|return\\s+nil,\\s+fmt\\.Errorf|return\\s+errors\\.New|throw\\s+new'}, {'function.not_in_skip_list': True}, {'function.not_source_matches_regex': '(?i)\\b(mock|test|fixture)'}]

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
                info = [f, f" — multi-vault-deposit-aborts-observer: pattern matched. See WIKI for details."]
                results.append(self.generate_result(info))
        return results
