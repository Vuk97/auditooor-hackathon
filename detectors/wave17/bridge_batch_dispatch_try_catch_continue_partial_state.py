"""
bridge-batch-dispatch-try-catch-continue-partial-state — generated from reference/patterns.dsl/bridge-batch-dispatch-try-catch-continue-partial-state.yaml
DO NOT EDIT BY HAND. Regenerate via: python3 tools/pattern-compile.py bridge-batch-dispatch-try-catch-continue-partial-state.yaml
Source: snowbridge-r109-source-mine-oak-v2-major-finding-5
"""

import sys
from pathlib import Path as _Path
sys.path.insert(0, str(_Path(__file__).resolve().parent.parent))
from _template_utils import is_vendored_or_test_contract, is_leaf_helper
from _predicate_engine import eval_preconditions, eval_function_match

from slither.detectors.abstract_detector import AbstractDetector, DetectorClassification


class BridgeBatchDispatchTryCatchContinuePartialState(AbstractDetector):
    ARGUMENT = "bridge-batch-dispatch-try-catch-continue-partial-state"
    HELP = "Cross-chain dispatcher loops over batched commands with per-command try/catch and continues after a failed command, consuming the message nonce/marking it delivered while applying only a subset of the commands. Source-chain assets are already locked/burned so the partial state cannot be rolled back."
    IMPACT = DetectorClassification.HIGH
    CONFIDENCE = DetectorClassification.MEDIUM
    WIKI = "https://github.com/Vuk97/auditooor/blob/main/reference/patterns.dsl/bridge-batch-dispatch-try-catch-continue-partial-state.yaml"
    WIKI_TITLE = "Cross-chain batch dispatcher continues after per-command revert (partial atomicity)"
    WIKI_DESCRIPTION = "A cross-chain inbound-message dispatcher iterates over a list of commands inside a single message envelope. Each command is wrapped in `try { handler(...) } catch { success = false; }`. The dispatcher continues to the next command after a revert and emits a single per-message event whose `success` field is the AND of all per-command results. The nonce is consumed (or sparse-bitmap bit is set) befo"
    WIKI_EXPLOIT_SCENARIO = "An attacker submits a batch message [CallContract, MintForeignToken]. CallContract is crafted to revert (e.g., target reverts on a specific calldata, or runs out of allotted gas via the gas-budget guard). The catch block sets success=false and the loop advances to MintForeignToken — except the implementation-specific gas-budget early-return triggers FIRST and the dispatcher exits the loop entirely"
    WIKI_RECOMMENDATION = "Choose ONE of two well-defined semantics and document it: (a) ATOMIC BATCH — wrap the loop body in a single try/catch and revert the entire transaction on any inner failure, or use a sub-call with `assembly { revert(...) }` to bubble the failure out; the relayer must resubmit. (b) ISOLATED BATCH — d"

    _PRECONDITIONS = [{'contract.source_matches_regex': '(?i)(dispatch|inboundMessage|outboundMessage|crossChain|bridge|relay|commands\\s*\\[)'}]
    _MATCH = [{'function.kind': 'external_or_public_or_internal'}, {'function.body_contains_regex': 'for\\s*\\([^)]*\\)\\s*\\{[\\s\\S]*?try\\s+[A-Za-z_][\\w\\.]*\\s*\\{?[\\s\\S]*?\\}\\s*catch\\s*\\{'}, {'function.body_contains_regex': 'catch\\s*(?:\\([^)]*\\))?\\s*\\{\\s*(?:success\\s*=\\s*false|emit\\s+\\w*[Ff]ailed|continue\\s*;|/\\*\\s*ignore\\s*\\*/)'}, {'function.body_not_contains_regex': 'catch\\s*(?:\\([^)]*\\))?\\s*\\{[^}]*\\brevert\\b'}, {'function.body_not_contains_regex': '(?:if\\s*\\(\\s*!\\s*success\\s*\\)\\s*revert|require\\s*\\(\\s*success\\s*[,)]|atomicBatch|allOrNothing)'}, {'function.not_in_skip_list': True}, {'function.not_leaf_helper': True}, {'function.not_source_matches_regex': '(?i)\\b(mock|test|fixture)'}]

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
                info = [f, f" — bridge-batch-dispatch-try-catch-continue-partial-state: pattern matched. See WIKI for details."]
                results.append(self.generate_result(info))
        return results
