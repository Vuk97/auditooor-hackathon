"""
arbitrum-block-number-is-l1-not-l2 — generated from reference/patterns.dsl/arbitrum-block-number-is-l1-not-l2.yaml
DO NOT EDIT BY HAND. Regenerate via: python3 tools/pattern-compile.py arbitrum-block-number-is-l1-not-l2.yaml
Source: auditooor-R73-chain-specific-arbitrum
"""

import sys
from pathlib import Path as _Path
sys.path.insert(0, str(_Path(__file__).resolve().parent.parent))
from _template_utils import is_vendored_or_test_contract, is_leaf_helper
from _predicate_engine import eval_preconditions, eval_function_match

from slither.detectors.abstract_detector import AbstractDetector, DetectorClassification


class ArbitrumBlockNumberIsL1NotL2(AbstractDetector):
    ARGUMENT = "arbitrum-block-number-is-l1-not-l2"
    HELP = "On Arbitrum (One / Nova / Sepolia), `block.number` returns the L1 block number — NOT the L2 block number. Contracts that use block.number as a time proxy or for voting snapshots are either extremely coarse-grained or incorrect if they expected L2 blocks."
    IMPACT = DetectorClassification.HIGH
    CONFIDENCE = DetectorClassification.HIGH
    WIKI = "https://github.com/Vuk97/auditooor/blob/main/reference/patterns.dsl/arbitrum-block-number-is-l1-not-l2.yaml"
    WIKI_TITLE = "block.number on Arbitrum returns L1 block, not L2 — voting/time logic broken"
    WIKI_DESCRIPTION = "Arbitrum's Nitro client exposes `block.number` as the parent L1 block at the time the L2 batch was posted. The value updates slowly (once per L1 block ≈ 12s) — not per L2 block. Contracts forked from mainnet that use block.number as (a) a voting snapshot (`snapshotAt = block.number`), (b) a time proxy (assuming 12s per block), or (c) an anti-front-run nonce end up with snapshots that don't change "
    WIKI_EXPLOIT_SCENARIO = "A governance contract takes a snapshot using `block.number` at proposal-creation. On Arbitrum, 5 seconds of L2 activity elapse before the L1 block advances — a user can propose + vote in the same `block.number` window, and the voting power snapshot is taken at the same L1 block (or ONE block later). An attacker who sees a proposal can route all their tokens to voting contracts within the same L1 b"
    WIKI_RECOMMENDATION = "On L2s, never use `block.number` as a chain-local time or ordering proxy. Use `ArbSys(0x0000000000000000000000000000000000000064).arbBlockNumber()` or `block.timestamp`. If voting power snapshotting requires an ordering on the L2, introduce a per-L2-block counter tracked by the protocol itself. For "

    _PRECONDITIONS = [{'contract.source_matches_regex': '(?i)block\\.number'}]
    _MATCH = [{'function.kind': 'internal_or_external'}, {'function.reads_block_number': True}, {'function.reads_block_number': True}, {'function.reads_block_number': True}, {'function.reads_block_number': True}, {'function.reads_block_number': True}, {'function.reads_block_number': True}, {'function.reads_block_number': True}, {'function.reads_block_number': True}, {'function.reads_block_number': True}, {'function.reads_block_number': True}, {'function.reads_block_number': True}, {'function.reads_block_number': True}, {'function.reads_block_number': True}, {'function.reads_block_number': True}, {'function.reads_block_number': True}, {'function.body_contains_regex': '\\bblock\\.number\\b'}, {'function.body_not_contains_regex': '(?i)(ArbSys|arbBlockNumber|arbOS|getL2Block|block\\.timestamp\\s*\\+|L2_BLOCK)'}, {'function.not_in_skip_list': True}, {'function.not_leaf_helper': True}, {'function.not_source_matches_regex': '(?i)\\b(mock|test|fixture)'}]

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
                info = [f, f" — arbitrum-block-number-is-l1-not-l2: pattern matched. See WIKI for details."]
                results.append(self.generate_result(info))
        return results
