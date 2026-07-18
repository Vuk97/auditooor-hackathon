"""
certora-makerdao-dai-debt-ceiling-line — generated from reference/patterns.dsl/certora-makerdao-dai-debt-ceiling-line.yaml
DO NOT EDIT BY HAND. Regenerate via: python3 tools/pattern-compile.py certora-makerdao-dai-debt-ceiling-line.yaml
Source: certora-dss-vat/debtCeilings
"""

import sys
from pathlib import Path as _Path
sys.path.insert(0, str(_Path(__file__).resolve().parent.parent))
from _template_utils import is_vendored_or_test_contract, is_leaf_helper
from _predicate_engine import eval_preconditions, eval_function_match

from slither.detectors.abstract_detector import AbstractDetector, DetectorClassification


class CertoraMakerdaoDaiDebtCeilingLine(AbstractDetector):
    ARGUMENT = "certora-makerdao-dai-debt-ceiling-line"
    HELP = "Vat mutator bumps Art/rate without re-asserting `Art*rate <= line[ilk]` — Maker Certora `debtCeilings` invariant violated."
    IMPACT = DetectorClassification.HIGH
    CONFIDENCE = DetectorClassification.MEDIUM
    WIKI = "https://github.com/Vuk97/auditooor/blob/main/reference/patterns.dsl/certora-makerdao-dai-debt-ceiling-line.yaml"
    WIKI_TITLE = "Maker Vat: Art/rate mutator skips debt-ceiling bound"
    WIKI_DESCRIPTION = "MakerDAO's Certora proofs show `Art[ilk] * rate[ilk] <= line[ilk]` at all times, and `debt <= Line` (global). The proof leans on every mutator (`frob` opening new debt, `drip` / `fold` rewriting the rate, `file` updating line) re-checking the bound. A patch that writes `rate[ilk]` up without re-checking `Art*rate <= line` lets an ilk silently exceed its ceiling; every new borrow against that ilk p"
    WIKI_EXPLOIT_SCENARIO = "A governance spell raises `rate[ETH-A]` via `fold(ETH-A, vow, dRate)`. Old rate was 1.05, new is 1.10; Art is 100M. Previously `Art*rate = 105M <= line = 110M`. After fold, `Art*rate = 110M`, exactly at cap. No re-check: a second fold to 1.15 pushes to 115M against line = 110M. Governance assumed the line would auto-revert the fold if over — it doesn't. Risk managers see ceiling-as-guardrail but i"
    WIKI_RECOMMENDATION = "Rate updates (`fold`), line updates (`file`), and any path that grows `Art` or shrinks `line` must re-assert `Art*rate <= line` and `debt <= Line`. Prove the Certora `debtCeilings` invariant on every Vat mutator."

    _PRECONDITIONS = [{'contract.has_state_var_matching': '(?i)(line|Line|Art|ilks|ilk|rate|debt)'}, {'contract.source_matches_regex': '(?i)(vat|dss|maker|ilk|debtCeiling)'}]
    _MATCH = [{'function.kind': 'external_or_public'}, {'function.is_mutating': True}, {'function.name_matches': '(?i)^(frob|drip|fold|file|init|_frob|accrue|updateRate|setLine|setCeiling)[A-Za-z0-9_]*'}, {'function.writes_storage_matching': '(?i)(Art|rate|line|Line|debt)'}, {'function.body_not_contains_regex': '(?i)(Art\\s*\\*\\s*rate\\s*<=\\s*line|Art\\s*\\*\\s*rate\\s*<\\s*line|debt\\s*<=\\s*Line|require[^;]*line|require[^;]*Line)'}, {'function.not_in_skip_list': True}, {'function.not_leaf_helper': True}, {'function.not_source_matches_regex': '(?i)\\b(mock|test|fixture)'}]

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
                info = [f, f" — certora-makerdao-dai-debt-ceiling-line: pattern matched. See WIKI for details."]
                results.append(self.generate_result(info))
        return results
