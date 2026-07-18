"""
transaction-ordering-race-umbrella - generated from reference/patterns.dsl/transaction-ordering-race-umbrella.yaml
DO NOT EDIT BY HAND. Regenerate via: python3 tools/pattern-compile.py transaction-ordering-race-umbrella.yaml
Source: hackerman-v2-slice2-batch2-local-conversion
"""

import sys
from pathlib import Path as _Path
sys.path.insert(0, str(_Path(__file__).resolve().parent.parent))
from _template_utils import is_vendored_or_test_contract, is_leaf_helper
from _predicate_engine import eval_preconditions, eval_function_match

from slither.detectors.abstract_detector import AbstractDetector, DetectorClassification


class TransactionOrderingRaceUmbrella(AbstractDetector):
    ARGUMENT = "transaction-ordering-race-umbrella"
    HELP = "Umbrella detector for transaction-ordering-race class: covers ERC20 approve frontrun, caller-side approve without zero-reset, governance proposal frontrunning, public nonce invalidation, withdrawal finalization races, and repay-on-behalf timing races. Source-shape only."
    IMPACT = DetectorClassification.MEDIUM
    CONFIDENCE = DetectorClassification.LOW
    WIKI = "https://github.com/Vuk97/auditooor/blob/main/reference/patterns.dsl/transaction-ordering-race-umbrella.yaml"
    WIKI_TITLE = "Transaction ordering race - umbrella detector (approve, proposal, nonce, withdrawal)"
    WIKI_DESCRIPTION = "Functions that update publicly observable value-bearing state (allowances, governance proposals, nonces, withdrawal queues, repay or liquidation state) without atomic commitment or race-condition guards are vulnerable to mempool-observation frontrunning. The five known subtypes represented by the fixture are: (1) ERC20 approve changes non-zero to non-zero without requiring zero-reset first; (2) go"
    WIKI_EXPLOIT_SCENARIO = "ERC20 contract calls approve(spender, 100). Before the tx confirms, spender front-runs by transferFrom for the current allowance (50). Then approve(spender, 100) confirms and spender calls transferFrom again for 100. Spender extracts 150 total instead of the intended 100."
    WIKI_RECOMMENDATION = "For approve: use increaseAllowance/decreaseAllowance or require existing allowance == 0 before setting new non-zero value. For governance: include a unique salt or nonce in proposal id and enforce proposal uniqueness atomically. For nonce invalidation: gate invalidation to the signer or burn the non"

    _PRECONDITIONS = [{'contract.source_matches_regex': '(?s)(approve|allowance|proposal|createProposal|governance|nonce|invalidat|cancelOrder|permit|finalizeWithdrawal|proveWithdrawal|withdrawal|repay|onBehalf|liquidat)'}]
    _MATCH = [{'function.kind': 'external_or_public'}, {'function.name_matches': '^(approve|set[A-Za-z0-9_]*Allowance|permit|createProposal|submitProposal|propose|cancelProposal|invalidate[A-Za-z0-9_]*|cancelOrder|finalize[A-Za-z0-9_]*(Withdrawal|Message)?|proveWithdrawalTransaction|repay[A-Za-z0-9_]*|isolateRepay|liquidate[A-Za-z0-9_]*)$'}, {'function.body_contains_regex': '(allowance|_allowances|proposal|proposalId|nonce|invalidat|orderStatus|withdrawal|provenAt|finalized|finalizeWithdrawal|repay|onBehalf|borrower|loan|lastAction|liquidat)'}, {'function.body_contains_regex': '(?s)(\\w+\\s*\\[[^\\]]+\\]\\s*(?:\\[[^\\]]+\\]\\s*)?(?:\\.\\s*\\w+\\s*)?\\s*(?:=|\\|=|\\+=|-=)|delete\\s+\\w+\\s*\\[[^\\]]+\\]|(?:lastAction|debt|amount|position|finalized)\\s*(?:=|\\+=|-=)|\\.\\s*(approve|permit|finalizeWithdrawal(?:Transaction)?)\\s*\\()'}, {'function.body_not_contains_regex': '(?s)(forceApprove|safeApprove|safeIncreaseAllowance|safeDecreaseAllowance|SafeERC20|increaseAllowance|decreaseAllowance|(?:allowance\\s*\\[[^\\]]*\\]\\s*\\[[^\\]]*\\]|currentAllowance|_allowance\\w*)\\s*==\\s*0|\\.approve\\s*\\(\\s*[A-Za-z_0-9.\\[\\]]+\\s*,\\s*0\\s*\\))'}, {'function.body_not_contains_regex': '(?s)(commit\\s*Reveal|commitReveal|uniqueSalt|proposalSalt|saltedId|require\\s*\\([^;]{0,240}(!proposals\\s*\\[|!hasProposal|!exists|EnumerableSet\\.contains|msg\\.sender\\s*==\\s*(maker|taker|signer|offerer|owner|borrower)|(?:maker|taker|signer|offerer|owner|borrower)\\s*==\\s*msg\\.sender|ownerOf\\s*\\([^)]*\\)\\s*==\\s*msg\\.sender|approvedRepayer\\s*\\[))'}, {'function.body_not_contains_regex': '(?s)(FaultDisputeGame|faultDisputeGame|DEFENDER_WINS|CHALLENGER_WINS|proofMaturityDelaySeconds|disputeGameFinalityDelaySeconds|superchainWithdrawalDelay|additionalWithdrawalDelay|notFinalized|finalityDelay)'}, {'function.not_in_skip_list': True}, {'function.not_leaf_helper': True}, {'function.not_source_matches_regex': '(?i)\\b(mock|test|fixture)\\b'}]

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
                info = [f, f" - transaction-ordering-race-umbrella: pattern matched. See WIKI for details."]
                results.append(self.generate_result(info))
        return results
