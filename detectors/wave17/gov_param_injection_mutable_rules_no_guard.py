"""
gov-param-injection-mutable-rules-no-guard - generated from reference/patterns.dsl/gov-param-injection-mutable-rules-no-guard.yaml
DO NOT EDIT BY HAND. Regenerate via: python3 tools/pattern-compile.py gov-param-injection-mutable-rules-no-guard.yaml
Source: capability-lift P1-07 gov-param-injection; anchors Solodit #21325/#21327/#41399/#11408 and Reserve #65128
"""

import sys
from pathlib import Path as _Path
sys.path.insert(0, str(_Path(__file__).resolve().parent.parent))
from _template_utils import is_vendored_or_test_contract, is_leaf_helper
from _predicate_engine import eval_preconditions, eval_function_match

from slither.detectors.abstract_detector import AbstractDetector, DetectorClassification


class GovParamInjectionMutableRulesNoGuard(AbstractDetector):
    ARGUMENT = "gov-param-injection-mutable-rules-no-guard"
    HELP = "Governance or proposal execution mutates rule-defining parameters without bounds, delay, snapshot, role, or immutable-domain constraints."
    IMPACT = DetectorClassification.MEDIUM
    CONFIDENCE = DetectorClassification.MEDIUM
    WIKI = "https://github.com/Vuk97/auditooor/blob/main/reference/patterns.dsl/gov-param-injection-mutable-rules-no-guard.yaml"
    WIKI_TITLE = "Governance parameter injection through mutable proposal or rule state"
    WIKI_DESCRIPTION = "A DAO, governor, optimistic proposal, or proposal execution path writes rule-defining state such as proposal metadata, fork thresholds, voting windows, token minting rights, route configuration, caps, or selector targets without any guard family. A malicious proposer can alter the rules voters thought they were voting under, or install a configuration that immediately changes execution rights."
    WIKI_EXPLOIT_SCENARIO = "A proposer submits an apparently acceptable proposal, then uses an update or execution path that rewrites the proposal payload, fork threshold, voting window, mint cap, route config, selector target, or governor parameter before voters or challengers can react. Because the path has no bounds, delay, snapshot, role, or immutable-domain check, the altered rules are consumed as if voters approved the"
    WIKI_RECOMMENDATION = "Bind proposal execution to immutable proposal hashes and snapshots. Add timelock or challenge delays to governance parameter changes, enforce min and max bounds for thresholds and caps, require explicit governance roles where appropriate, reject zero-address route/governor config, and invalidate vot"

    _PRECONDITIONS = [{'contract.source_matches_regex': '(?i)(govern|governance|dao|proposal|proposer|vote|voting|fork|threshold|quorum|timelock|selector|registry|route|cap|limit|mint|token|parameter|config|window)'}, {'contract.has_state_var_matching': '(?i)(proposal|payload|metadata|description|hash|fork|threshold|quorum|voting|vote|window|delay|period|timelock|selector|registry|route|cap|limit|mint|distribution|governor|parameter|config)'}]
    _MATCH = [{'function.kind': 'external_or_public'}, {'function.name_matches_regex': '(?i)^(execute|executeProposal|finalize|finalizeProposal|apply|applyProposal|enact|enactProposal|propose|createProposal|submitProposal|updateProposal|amendProposal|setGovernanceParameter|setParameter|set[A-Z].*Parameter|configure[A-Z].*|update[A-Z].*Config|setRoute|setSelector|registerSelector|initialize|mintGTToAddress|claimDuringForkPeriod|executeFork)$'}, {'function.not_in_skip_list': True}, {'function.writes_state_var_matching_regex': '(?i)(proposal|payload|metadata|description|hash|fork|threshold|quorum|voting|vote|window|delay|period|timelock|selector|registry|route|cap|limit|mint|distribution|governor|parameter|config)'}, {'function.body_contains_regex': '(?i)(proposalPayloadHash\\s*\\[|payloadHash\\s*\\[|proposals\\s*\\[|\\.payloadHash\\s*=|\\.proposalHash\\s*=|\\.descriptionHash\\s*=|fork(ing)?Period(EndTimestamp)?\\s*=|forkEndTimestamp|forkThreshold\\s*=|proposalThreshold\\s*=|quorum(Votes|Bps)?\\s*=|voting(Delay|Period|Window)\\s*=|timelockDelay\\s*=|governanceParameters?\\s*\\[|parameters?\\s*\\[|route(Config)?\\s*\\[|selector(Target|Registry)?\\s*\\[|mintCap\\s*=|distributionAmount\\s*=|minted[A-Za-z0-9_]*\\s*(\\+\\+|\\+=|=)|cap\\s*=|limit\\s*=|governor\\s*=|_mint\\s*\\(|\\.mint\\s*\\(|setSelector\\s*\\(|setRoute\\s*\\()'}, {'function.body_not_contains_regex': '(?i)(onlyOwner|onlyGov|onlyGovernance|onlyRole|hasRole|AccessControl|timelock|delay|eta|readyAt|queuedAt|executeAfter|block\\.timestamp\\s*[<>]=\\s*.*(readyAt|eta|delay|timelock)|block\\.number\\s*[<>]=\\s*.*(snapshot|startBlock)|getPastVotes|balanceAt|votesAt|snapshot|proposalSnapshot|currentHash|expectedHash|proposalVersion|proposalNonce|invalidate|notice|voterNotice|MIN_|MAX_|\\b(min|max)(Value|imum|Bound|Cap|Delay|Window|Threshold)\\b|bounds?|validate[A-Z]|check[A-Z]|nonZero|address\\s*\\(\\s*0\\s*\\)|immutable|DOMAIN_SEPARATOR|chainid)'}, {'function.modifiers_not_matching': '(?i)(onlyOwner|onlyGov|onlyGovernance|onlyRole|requiresRole|timelock|delayed|bounded|nonZero|valid|snapshot)'}, {'function.not_source_matches_regex': '(?i)\\b(mock|test|fixture)\\b'}]

    _INCLUDE_LEAF_HELPERS = True
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
                info = [f, f" - gov-param-injection-mutable-rules-no-guard: pattern matched. See WIKI for details."]
                results.append(self.generate_result(info))
        return results
