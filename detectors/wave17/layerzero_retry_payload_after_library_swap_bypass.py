"""
layerzero-retry-payload-after-library-swap-bypass — generated from reference/patterns.dsl/layerzero-retry-payload-after-library-swap-bypass.yaml
DO NOT EDIT BY HAND. Regenerate via: python3 tools/pattern-compile.py layerzero-retry-payload-after-library-swap-bypass.yaml
Source: auditooor-R75-zellic-mellow-layerzero-HIGH
"""

import sys
from pathlib import Path as _Path
sys.path.insert(0, str(_Path(__file__).resolve().parent.parent))
from _template_utils import is_vendored_or_test_contract, is_leaf_helper
from _predicate_engine import eval_preconditions, eval_function_match

from slither.detectors.abstract_detector import AbstractDetector, DetectorClassification


class LayerzeroRetryPayloadAfterLibrarySwapBypass(AbstractDetector):
    ARGUMENT = "layerzero-retry-payload-after-library-swap-bypass"
    HELP = "When a cross-chain endpoint stores payloads that failed to deliver under library X and later allows retryPayload to re-invoke the UA, swapping to a new trusted library Y without clearing the stored payload bucket lets the old (now-untrusted) library's payloads still reach the UA via retry."
    IMPACT = DetectorClassification.HIGH
    CONFIDENCE = DetectorClassification.MEDIUM
    WIKI = "https://github.com/Vuk97/auditooor/blob/main/reference/patterns.dsl/layerzero-retry-payload-after-library-swap-bypass.yaml"
    WIKI_TITLE = "Cross-chain library swap does not clear stored-payload queue (retry-after-revoke)"
    WIKI_DESCRIPTION = "LayerZero-style endpoints track (a) the currently-trusted receive library per-UA and (b) a storedPayload mapping for messages that reverted on first delivery. The library-address check is performed at first-receive but NOT at retryPayload. If an operator replaces a compromised library, any payload that the old compromised library already pushed into storedPayload can still be retried and delivered"
    WIKI_EXPLOIT_SCENARIO = "Untrusted ULN X pushes a malicious message into storedPayload (message reverts the first time for any reason — e.g., UA's lzReceive OOG). Operator discovers X is compromised and setReceiveLibrary(Y). Attacker calls retryPayload; the retry path does not re-check that the library that stored the payload is still trusted, so the malicious message executes as if delivered by Y."
    WIKI_RECOMMENDATION = "In setReceiveLibrary / setSendLibrary (and default-library setters), either (a) delete all storedPayload entries for that UA, or (b) record the library address alongside the stored payload and require retryPayload to verify the stored library still matches the current trusted library."

    _PRECONDITIONS = [{'contract.source_matches_regex': '(receiveLibraryAddress|defaultReceiveLibraryAddress|storedPayload|retryPayload|uaConfig)'}]
    _MATCH = [{'function.kind': 'external_or_public'}, {'function.name_matches': '(setReceiveLibrary|setSendLibrary|upgradeLibrary|setDefaultLibrary|migrateLibrary)'}, {'function.body_not_contains_regex': '(storedPayload\\[[^\\]]+\\]\\s*=\\s*StoredPayload\\(0|delete\\s+storedPayload|forceResumeReceive|_clearStoredPayloads)'}, {'function.not_in_skip_list': True}, {'function.not_leaf_helper': True}, {'function.not_source_matches_regex': '(?i)\\b(mock|test|fixture)'}]

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
                info = [f, f" — layerzero-retry-payload-after-library-swap-bypass: pattern matched. See WIKI for details."]
                results.append(self.generate_result(info))
        return results
