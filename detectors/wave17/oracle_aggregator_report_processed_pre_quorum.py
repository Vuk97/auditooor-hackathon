"""
oracle-aggregator-report-processed-pre-quorum — generated from reference/patterns.dsl/oracle-aggregator-report-processed-pre-quorum.yaml
DO NOT EDIT BY HAND. Regenerate via: python3 tools/pattern-compile.py oracle-aggregator-report-processed-pre-quorum.yaml
Source: auditooor-R68-kiln-vSuite-M7
"""

import sys
from pathlib import Path as _Path
sys.path.insert(0, str(_Path(__file__).resolve().parent.parent))
from _template_utils import is_vendored_or_test_contract, is_leaf_helper
from _predicate_engine import eval_preconditions, eval_function_match

from slither.detectors.abstract_detector import AbstractDetector, DetectorClassification


class OracleAggregatorReportProcessedPreQuorum(AbstractDetector):
    ARGUMENT = "oracle-aggregator-report-processed-pre-quorum"
    HELP = "Oracle aggregator's submit path advances state (share rate, total supply, epoch consumed) as soon as a member submits, without requiring quorum to be reached. A single member can set the aggregator's output value before honest members vote."
    IMPACT = DetectorClassification.MEDIUM
    CONFIDENCE = DetectorClassification.MEDIUM
    WIKI = "https://github.com/Vuk97/auditooor/blob/main/reference/patterns.dsl/oracle-aggregator-report-processed-pre-quorum.yaml"
    WIKI_TITLE = "Oracle aggregator processes report before reaching quorum"
    WIKI_DESCRIPTION = "`OracleAggregator.submitReport(data)` (or sibling `reportData` / `pushReport`) is called once per member per epoch. The function records the member's vote AND advances the aggregator's stored state in the same transaction, without a guard that verifies the number of submissions has reached the quorum threshold. If the downstream consumer (protocol that reads `getLatestReport`) accepts the aggregat"
    WIKI_EXPLOIT_SCENARIO = "A liquid-staking protocol's `vOracleAggregator` requires quorum = 3 of 5 members to advance `$lastReport.shareRate`. Member 1 submits a lowball report (1000 wei per share). The aggregator writes `$lastReport.shareRate = 1000` immediately — no quorum check. A downstream consumer (`vPool.convertToShares`) reads the aggregator and computes mint-share amounts against the rogue rate. Users depositing i"
    WIKI_RECOMMENDATION = "Separate vote-recording from state-advancement:\n\n```solidity\nfunction submitReport(bytes data) external onlyMember {\n    votes[msg.sender][epoch] = data;\n    voteCount[epoch]++;\n    emit VoteRecorded(msg.sender, epoch);\n    // Do NOT mutate $lastReport here.\n}\n\nfunction finalizeReport(uint"

    _PRECONDITIONS = [{'contract.source_matches_regex': '.*'}, {'contract.has_state_var_matching': 'quorum|threshold|members|[A-Z][a-zA-Z]*Oracle|OracleMember'}]
    _MATCH = [{'function.kind': 'external_or_public'}, {'function.name_matches': 'submitReport|reportData|postReport|pushReport|submitOracle|consumeReport|advanceReport'}, {'function.has_high_level_call_named': 'totalSupply'}, {'function.has_high_level_call_named': 'totalSupply'}, {'function.has_high_level_call_named': 'totalSupply'}, {'function.has_high_level_call_named': 'totalSupply'}, {'function.has_high_level_call_named': 'totalSupply'}, {'function.has_high_level_call_named': 'totalSupply'}, {'function.has_high_level_call_named': 'totalSupply'}, {'function.has_high_level_call_named': 'totalSupply'}, {'function.has_high_level_call_named': 'totalSupply'}, {'function.has_high_level_call_named': 'totalSupply'}, {'function.has_high_level_call_named': 'totalSupply'}, {'function.has_high_level_call_named': 'totalSupply'}, {'function.has_high_level_call_named': 'totalSupply'}, {'function.has_high_level_call_named': 'totalSupply'}, {'function.body_contains_regex': '\\$[a-zA-Z]+|[a-zA-Z]+Storage(Lib)?\\.set[A-Z]|[a-zA-Z_.]+\\s*=\\s*report\\s*[;.,]|totalSupply\\s*=|shareRate\\s*='}, {'function.body_not_contains_regex': 'require\\s*\\(\\s*[a-zA-Z_.]+\\s*>=\\s*[a-zA-Z_.]*(quorum|threshold|required|minimum)|if\\s*\\(\\s*[a-zA-Z_.]+\\s*<\\s*[a-zA-Z_.]*(quorum|threshold|required|minimum)'}, {'function.body_contains_regex': '(vote|voting|submitted|memberReports)\\[[^\\]]+\\]\\s*=|(vote|voting)\\+\\+|(voteCount|memberCount)'}, {'function.not_in_skip_list': True}, {'function.not_leaf_helper': True}, {'function.not_source_matches_regex': '(?i)\\b(mock|test|fixture)'}]

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
                info = [f, f" — oracle-aggregator-report-processed-pre-quorum: pattern matched. See WIKI for details."]
                results.append(self.generate_result(info))
        return results
