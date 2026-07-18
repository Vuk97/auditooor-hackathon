"""
solana-account-duplicate-in-instruction-accounts — generated from reference/patterns.dsl/solana-account-duplicate-in-instruction-accounts.yaml
DO NOT EDIT BY HAND. Regenerate via: python3 tools/pattern-compile.py solana-account-duplicate-in-instruction-accounts.yaml
Source: auditooor-R73-chain-specific-solana
"""

import sys
from pathlib import Path as _Path
sys.path.insert(0, str(_Path(__file__).resolve().parent.parent))
from _template_utils import is_vendored_or_test_contract, is_leaf_helper
from _predicate_engine import eval_preconditions, eval_function_match

from slither.detectors.abstract_detector import AbstractDetector, DetectorClassification


class SolanaAccountDuplicateInInstructionAccounts(AbstractDetector):
    ARGUMENT = "solana-account-duplicate-in-instruction-accounts"
    HELP = "Solana/Anchor programs that validate a specific account by index without checking uniqueness across the accounts array allow duplicate-account injection; downstream PDA lookups can match the wrong account. Seen on LayerZero-v2 Solana endpoint."
    IMPACT = DetectorClassification.HIGH
    CONFIDENCE = DetectorClassification.MEDIUM
    WIKI = "https://github.com/Vuk97/auditooor/blob/main/reference/patterns.dsl/solana-account-duplicate-in-instruction-accounts.yaml"
    WIKI_TITLE = "Solana instruction accounts not validated unique — duplicate sender confuses CPI dispatch"
    WIKI_DESCRIPTION = "Anchor's `ctx.accounts.X` or raw `AccountInfo[]` access relies on account indexing. If a program checks `accounts[1].key == expected` but doesn't ALSO ensure that `expected` appears only once in the accounts slice, a caller can insert the expected account at index 1 AND at some later index (e.g. index 5 where a DVN or custody PDA is expected). Downstream code that scans the account list looking fo"
    WIKI_EXPLOIT_SCENARIO = "A cross-chain bridge on Solana expects `accounts = [authority, sender_pda, mesg_pda, dvn_1_pda, dvn_2_pda]`. Caller submits `accounts = [authority, sender_pda, mesg_pda, sender_pda, dvn_2_pda]`. Program validates `accounts[1] == sender_pda`, passes. Code downstream iterates `accounts[3..]` looking for DVN accounts — finds `sender_pda` as index 3, matches some loose 'has PDA-owner' check because bo"
    WIKI_RECOMMENDATION = "Use Anchor's `#[account(constraint = ...)]` with explicit `ctx.accounts.X.key() != ctx.accounts.Y.key()` checks. In raw solana_program code, insert a `HashSet<Pubkey>` check: `let mut seen = HashSet::new(); for a in accounts { assert!(seen.insert(a.key), \"duplicate\"); }`. For any fixed-position ac"

    _PRECONDITIONS = [{'contract.source_matches_regex': '(?i)anchor|#\\[account|solana_program|AccountInfo|accounts\\['}]
    _MATCH = [{'function.kind': 'external_or_public_or_internal'}, {'function.body_contains_regex': '(?i)accounts\\s*\\[\\s*\\d+\\s*\\]|ctx\\.accounts\\.\\w+'}, {'function.body_not_contains_regex': '(?i)(#\\[account\\(mut,\\s*has_one|constraint\\s*=|filter\\(\\|\\w+\\|\\s*\\w+\\.key\\s*==|HashSet|unique)'}, {'function.not_in_skip_list': True}, {'function.not_leaf_helper': True}, {'function.not_source_matches_regex': '(?i)\\b(mock|test|fixture)'}]

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
                info = [f, f" — solana-account-duplicate-in-instruction-accounts: pattern matched. See WIKI for details."]
                results.append(self.generate_result(info))
        return results
