"""
erc1155-batch-length-mismatch-allows-partial — generated from reference/patterns.dsl/erc1155-batch-length-mismatch-allows-partial.yaml
DO NOT EDIT BY HAND. Regenerate via: python3 tools/pattern-compile.py erc1155-batch-length-mismatch-allows-partial.yaml
Source: solodit/erc1155-batch-length-class
"""

import sys
from pathlib import Path as _Path
sys.path.insert(0, str(_Path(__file__).resolve().parent.parent))
from _template_utils import is_vendored_or_test_contract, is_leaf_helper
from _predicate_engine import eval_preconditions, eval_function_match

from slither.detectors.abstract_detector import AbstractDetector, DetectorClassification


class Erc1155BatchLengthMismatchAllowsPartial(AbstractDetector):
    ARGUMENT = "erc1155-batch-length-mismatch-allows-partial"
    HELP = "ERC1155 batch mint/burn/transfer accepts parallel `ids` and `amounts` arrays but omits the `require(ids.length == amounts.length)` guard. Either the loop panics out-of-bounds (when amounts is shorter) or accounting silently truncates (when the bookkeeping uses one length while the loop uses the othe"
    IMPACT = DetectorClassification.MEDIUM
    CONFIDENCE = DetectorClassification.MEDIUM
    WIKI = "https://github.com/Vuk97/auditooor/blob/main/reference/patterns.dsl/erc1155-batch-length-mismatch-allows-partial.yaml"
    WIKI_TITLE = "ERC1155 batch entry accepts unequal ids/amounts arrays — partial execution or OOB panic"
    WIKI_DESCRIPTION = "Every ERC1155 batch entry point — `batchMint`, `batchBurn`, `_safeBatchTransferFrom`, and their variants — takes two caller-supplied arrays that are required to represent the same i-th (token, quantity) tuple. The OpenZeppelin reference enforces `require(ids.length == amounts.length)` at the top of `_update`. Forks and bespoke ERC1155-style implementations (game items, utility tokens, fractionalis"
    WIKI_EXPLOIT_SCENARIO = "A token contract exposes `mintBatch(address to, uint256[] calldata ids, uint256[] calldata amounts)` that iterates with `for (uint i = 0; i < ids.length; i++) _balances[ids[i]][to] += amounts[i];` and emits `TransferBatch(..., ids, amounts)`. An attacker with mint rights (or a privileged script bug) submits `ids = [1, 2, 3, 4, 5]` and `amounts = [100, 100]`. On Solidity 0.8 the third iteration rev"
    WIKI_RECOMMENDATION = "Add `require(ids.length == amounts.length, \"ERC1155: array length mismatch\")` at the top of every batch entry point before any state write. When overriding `_update` in an OpenZeppelin-derived contract, call `super._update(...)` so the parent-class check still runs. Where the codebase already uses"

    _PRECONDITIONS = [{'contract.source_matches_regex': '.*'}]
    _MATCH = [{'function.kind': 'external_or_public'}, {'function.name_matches': 'batchMint|batchBurn|batchTransfer|_batchMint|_batchBurn|_safeBatchTransferFrom|mintBatch|burnBatch'}, {'function.body_contains_regex': 'ids\\[\\s*i\\s*\\]|ids\\.length|amounts\\.length'}, {'function.body_not_contains_regex': 'require\\s*\\(\\s*ids\\.length\\s*==\\s*amounts\\.length|require\\s*\\(\\s*amounts\\.length\\s*==\\s*ids\\.length'}, {'function.not_in_skip_list': True}, {'function.not_leaf_helper': True}, {'function.not_source_matches_regex': '(?i)\\b(mock|test|fixture)'}]

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
                info = [f, f" — erc1155-batch-length-mismatch-allows-partial: pattern matched. See WIKI for details."]
                results.append(self.generate_result(info))
        return results
