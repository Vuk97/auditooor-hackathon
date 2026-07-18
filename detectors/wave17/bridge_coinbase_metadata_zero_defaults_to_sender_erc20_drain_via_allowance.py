"""
bridge-coinbase-metadata-zero-defaults-to-sender-erc20-drain-via-allowance — generated from reference/patterns.dsl/bridge-coinbase-metadata-zero-defaults-to-sender-erc20-drain-via-allowance.yaml
DO NOT EDIT BY HAND. Regenerate via: python3 tools/pattern-compile.py bridge-coinbase-metadata-zero-defaults-to-sender-erc20-drain-via-allowance.yaml
Source: auditooor-R75-c4-mined-2024-03-taiko-163
"""

import sys
from pathlib import Path as _Path
sys.path.insert(0, str(_Path(__file__).resolve().parent.parent))
from _template_utils import is_vendored_or_test_contract, is_leaf_helper
from _predicate_engine import eval_preconditions, eval_function_match

from slither.detectors.abstract_detector import AbstractDetector, DetectorClassification


class BridgeCoinbaseMetadataZeroDefaultsToSenderErc20DrainViaAllowance(AbstractDetector):
    ARGUMENT = "bridge-coinbase-metadata-zero-defaults-to-sender-erc20-drain-via-allowance"
    HELP = "`proposeBlock` defaults `params.coinbase` to `msg.sender` when zero, but the `AssignmentHook` later uses `meta.coinbase` as the `from` address in `ERC20.safeTransferFrom(meta.coinbase, assignedProver, proverFee)` WITHOUT requiring the proposer to sign over coinbase. A malicious proposer can set `par"
    IMPACT = DetectorClassification.HIGH
    CONFIDENCE = DetectorClassification.MEDIUM
    WIKI = "https://github.com/Vuk97/auditooor/blob/main/reference/patterns.dsl/bridge-coinbase-metadata-zero-defaults-to-sender-erc20-drain-via-allowance.yaml"
    WIKI_TITLE = "Proposer-supplied coinbase lets attacker drain anyone's ERC20 allowance on block-proposal hook"
    WIKI_DESCRIPTION = "In rollup block proposal, `params.coinbase` is the address credited with block rewards / MEV. The code defaults `params.coinbase = msg.sender` if zero, but accepts any nonzero value from the proposer. The coinbase field is then stored into `meta.coinbase` and forwarded to `AssignmentHook.onBlockProposed(meta)`, which pays the assigned prover via `IERC20(feeToken).safeTransferFrom(meta.coinbase, as"
    WIKI_EXPLOIT_SCENARIO = "Alice is a legitimate proposer. She approves AssignmentHook for 10 ether to cover multiple future blocks. After proposing one block (fee = 0.1), 9.9 ether allowance remains. Mallory observes the residual allowance. Mallory calls `proposeBlock(params)` with `params.coinbase = Alice`. The assignment hook calls `ERC20(feeToken).safeTransferFrom(Alice, Mallory's assignedProver, 0.1 ether)`. Mallory ea"
    WIKI_RECOMMENDATION = "If `params.coinbase` is nonzero, require ECDSA signature by coinbase consenting to this block (EIP-712), OR force coinbase = msg.sender unconditionally. Never use a user-selected address as the `from` argument of safeTransferFrom without either (a) explicit consent or (b) allowance carefully scoped "

    _PRECONDITIONS = [{'contract.source_matches_regex': 'LibProposing|proposeBlock|AssignmentHook'}]
    _MATCH = [{'function.kind': 'external_or_public_or_internal'}, {'function.name_matches': '^(proposeBlock|onBlockProposed|_propose)$'}, {'function.body_contains_regex': 'params\\.coinbase\\s*==\\s*address\\s*\\(\\s*0\\s*\\)\\s*\\)\\s*\\{[^}]*params\\.coinbase\\s*=\\s*msg\\.sender|meta\\.coinbase\\s*=\\s*msg\\.sender'}, {'function.has_high_level_call_named': 'safeTransferFrom|safeTransfer'}, {'function.has_high_level_call_named': 'safeTransferFrom|safeTransfer'}, {'function.has_high_level_call_named': 'safeTransferFrom|safeTransfer'}, {'function.has_high_level_call_named': 'safeTransferFrom|safeTransfer'}, {'function.has_high_level_call_named': 'safeTransferFrom|safeTransfer'}, {'function.has_high_level_call_named': 'safeTransferFrom|safeTransfer'}, {'function.has_high_level_call_named': 'safeTransferFrom|safeTransfer'}, {'function.has_high_level_call_named': 'safeTransferFrom|safeTransfer'}, {'function.has_high_level_call_named': 'safeTransferFrom|safeTransfer'}, {'function.has_high_level_call_named': 'safeTransferFrom|safeTransfer'}, {'function.has_high_level_call_named': 'safeTransferFrom|safeTransfer'}, {'function.has_high_level_call_named': 'safeTransferFrom|safeTransfer'}, {'function.has_high_level_call_named': 'safeTransferFrom|safeTransfer'}, {'function.body_contains_regex': 'safeTransferFrom\\s*\\(\\s*(_meta\\.coinbase|meta\\.coinbase|params\\.coinbase)'}, {'function.not_in_skip_list': True}, {'function.not_leaf_helper': True}, {'function.not_source_matches_regex': '(?i)\\b(mock|test|fixture)'}]

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
                info = [f, f" — bridge-coinbase-metadata-zero-defaults-to-sender-erc20-drain-via-allowance: pattern matched. See WIKI for details."]
                results.append(self.generate_result(info))
        return results
