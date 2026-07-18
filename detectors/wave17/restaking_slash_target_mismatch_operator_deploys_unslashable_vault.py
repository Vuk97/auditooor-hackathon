"""
restaking-slash-target-mismatch-operator-deploys-unslashable-vault — generated from reference/patterns.dsl/restaking-slash-target-mismatch-operator-deploys-unslashable-vault.yaml
DO NOT EDIT BY HAND. Regenerate via: python3 tools/pattern-compile.py restaking-slash-target-mismatch-operator-deploys-unslashable-vault.yaml
Source: auditooor-R75-c4-mined-2024-07-karak-55
"""

import sys
from pathlib import Path as _Path
sys.path.insert(0, str(_Path(__file__).resolve().parent.parent))
from _template_utils import is_vendored_or_test_contract, is_leaf_helper
from _predicate_engine import eval_preconditions, eval_function_match

from slither.detectors.abstract_detector import AbstractDetector, DetectorClassification


class RestakingSlashTargetMismatchOperatorDeploysUnslashableVault(AbstractDetector):
    ARGUMENT = "restaking-slash-target-mismatch-operator-deploys-unslashable-vault"
    HELP = "Review-lead detector for a restaking slash path that compares a canonical slashingHandler against a vault-local slashStore. Fixture smoke only; manual proof is required for operator control, call-chain reachability, and impact."
    IMPACT = DetectorClassification.LOW
    CONFIDENCE = DetectorClassification.LOW
    WIKI = "https://github.com/Vuk97/auditooor/blob/main/reference/patterns.dsl/restaking-slash-target-mismatch-operator-deploys-unslashable-vault.yaml"
    WIKI_TITLE = "Possible operator-controlled slashStore mismatch in restaking vault slash path"
    WIKI_DESCRIPTION = "This detector flags a source shape where a slash entry point rejects when slashingHandler differs from a vault-local slashStore. The fixture shows the static shape only. A real finding still needs proof that the slashStore is operator-controlled at initialization, differs from the canonical asset handler, and blocks a reachable slash."
    WIKI_EXPLOIT_SCENARIO = "Review-lead only: investigate deployVaults or initialization flow for attacker/operator control of slashStore, then prove a later canonical slash attempt reaches slashAssets and reverts because the stored slashStore is not the canonical handler. Do not file from this detector hit alone."
    WIKI_RECOMMENDATION = "Bind slashStore to the canonical assetSlashingHandlers entry during initialization or resolve the canonical handler at slash time. Add invariant tests that vault slash paths accept the canonical handler and cannot be initialized with a mismatched handler."

    _PRECONDITIONS = [{'contract.source_matches_regex': 'NativeVault|Vault|SlasherLib|slashAssets|slashStore'}]
    _MATCH = [{'function.kind': 'external_or_public_or_internal'}, {'function.name_matches': '^(slashAssets|_slash|executeSlashing)$'}, {'function.body_contains_regex': 'slashingHandler\\s*!=\\s*(self\\.slashStore|slashStore|_slashStore)|revert\\s+NotSlashStore'}, {'function.body_not_contains_regex': '(slashStore\\s*=\\s*\\w+\\.assetSlashingHandlers|slashStore\\s*=\\s*globalSlashingHandler|initializer\\s+config\\.slashStore|slashStore\\s+canonical|require\\s*\\(\\s*slashStore\\s*==\\s*registry)'}, {'function.not_in_skip_list': True}, {'function.not_leaf_helper': True}, {'function.not_source_matches_regex': '(?i)\\b(mock|test|fixture)'}]

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
                info = [f, f" — restaking-slash-target-mismatch-operator-deploys-unslashable-vault: pattern matched. See WIKI for details."]
                results.append(self.generate_result(info))
        return results
