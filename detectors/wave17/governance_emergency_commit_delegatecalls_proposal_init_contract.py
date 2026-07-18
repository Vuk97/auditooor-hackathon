"""
governance-emergency-commit-delegatecalls-proposal-init-contract — generated from reference/patterns.dsl/governance-emergency-commit-delegatecalls-proposal-init-contract.yaml
DO NOT EDIT BY HAND. Regenerate via: python3 tools/pattern-compile.py governance-emergency-commit-delegatecalls-proposal-init-contract.yaml
Source: auditooor-R76-rekt-beanstalk-2022
"""

import sys
from pathlib import Path as _Path
sys.path.insert(0, str(_Path(__file__).resolve().parent.parent))
from _template_utils import is_vendored_or_test_contract, is_leaf_helper
from _predicate_engine import eval_preconditions, eval_function_match

from slither.detectors.abstract_detector import AbstractDetector, DetectorClassification


class GovernanceEmergencyCommitDelegatecallsProposalInitContract(AbstractDetector):
    ARGUMENT = "governance-emergency-commit-delegatecalls-proposal-init-contract"
    HELP = "Governance finalization delegatecalls a proposal-supplied `init` contract with no whitelist and no timelock enforcement in the body, so any passed proposal can execute arbitrary bytecode in the governance contract's storage context and drain assets."
    IMPACT = DetectorClassification.MEDIUM
    CONFIDENCE = DetectorClassification.HIGH
    WIKI = "https://github.com/Vuk97/auditooor/blob/main/reference/patterns.dsl/governance-emergency-commit-delegatecalls-proposal-init-contract.yaml"
    WIKI_TITLE = "Governance executes proposal-supplied init contract via unchecked delegatecall"
    WIKI_DESCRIPTION = "Some governance systems let a proposal carry a pointer to an `init` (or `execute`) contract; on `commit` / `emergencyCommit` the governance contract delegatecalls that pointer. If the pointer is not compared against a trusted list, and no timelock delay sits between proposal pass and delegatecall, any attacker who can acquire momentary majority voting power (flash-loan deposit into a governance-we"
    WIKI_EXPLOIT_SCENARIO = "Attacker takes a flash loan, LPs into BEAN-3CRV + BEAN-LUSD, gets enough stalk to satisfy 2/3 supermajority. Attacker pre-posted malicious BIP-18 (initAddress = InitBip18 which transfers balances to attacker). Attacker calls `emergencyCommit(BIP-18)`; governance checks quorum passes; governance delegatecalls `InitBip18.init()` which transfers ~$181M out. Attacker unwinds LP and repays flash loan."
    WIKI_RECOMMENDATION = "Require a non-zero timelock between proposal acceptance and delegatecall (force attackers to hold the voting power for >=1 block beyond flash-loan scope). Maintain an explicit whitelist of allowed init-contract bytecode hashes, or forbid arbitrary delegatecall in the committed execution path entirel"

    _PRECONDITIONS = [{'contract.source_matches_regex': '.*'}, 'Governance contract executes a passed proposal by delegatecalling an `init` / `execute` address supplied in the proposal metadata.']
    _MATCH = [{'function.kind': 'external'}, {'function.name_matches': '(?i)emergencyCommit|commit|executeProposal|executeBIP|queueAndExecute|execute$'}, {'function.has_low_level_call': {'op': 'delegatecall'}}, {'function.has_low_level_call': {'op': 'delegatecall'}}, {'function.has_low_level_call': {'op': 'delegatecall'}}, {'function.has_low_level_call': {'op': 'delegatecall'}}, {'function.body_contains_regex': '(?i)delegatecall|functionDelegateCall|initAddress|proposalAddr|\\.call\\s*\\(.*init'}, {'function.body_not_contains_regex': '(?i)trustedInitList|whitelistedInit|allowedExecutor|timelock\\.minDelay|executorWhitelist|require\\s*\\([^;]*initAddress\\s*\\)\\s*=='}, {'function.not_in_skip_list': True}, {'function.not_leaf_helper': True}, {'function.not_source_matches_regex': '(?i)\\b(mock|test|fixture)'}]

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
                info = [f, f" — governance-emergency-commit-delegatecalls-proposal-init-contract: pattern matched. See WIKI for details."]
                results.append(self.generate_result(info))
        return results
