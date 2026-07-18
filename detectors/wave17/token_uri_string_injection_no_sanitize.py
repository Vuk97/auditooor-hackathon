"""
token-uri-string-injection-no-sanitize — generated from reference/patterns.dsl/token-uri-string-injection-no-sanitize.yaml
DO NOT EDIT BY HAND. Regenerate via: python3 tools/pattern-compile.py token-uri-string-injection-no-sanitize.yaml
Source: solodit/C0060
"""

import sys
from pathlib import Path as _Path
sys.path.insert(0, str(_Path(__file__).resolve().parent.parent))
from _template_utils import is_vendored_or_test_contract, is_leaf_helper
from _predicate_engine import eval_preconditions, eval_function_match

from slither.detectors.abstract_detector import AbstractDetector, DetectorClassification


class TokenUriStringInjectionNoSanitize(AbstractDetector):
    ARGUMENT = "token-uri-string-injection-no-sanitize"
    HELP = "tokenURI / metadata renderer splices user-controlled token name or symbol directly into JSON without escaping — JSON injection / off-chain XSS on marketplaces."
    IMPACT = DetectorClassification.MEDIUM
    CONFIDENCE = DetectorClassification.LOW
    WIKI = "https://github.com/Vuk97/auditooor/blob/main/reference/patterns.dsl/token-uri-string-injection-no-sanitize.yaml"
    WIKI_TITLE = "Unsanitized user string in tokenURI / metadata renderer: JSON injection"
    WIKI_DESCRIPTION = "Contracts that build their tokenURI or contractURI JSON on-chain by concatenating a token.name() / token.symbol() / user-supplied description into a JSON string expose marketplace frontends to JSON injection and cross-site scripting. Quotes, backslashes, and control characters from the symbol break the JSON and can inject new keys or script payloads."
    WIKI_EXPLOIT_SCENARIO = "Attacker deploys an ERC20 with symbol: `X\",\"image\":\"javascript:alert(1)//`. A derivative NFT embeds that symbol verbatim in its tokenURI JSON. OpenSea / rendering frontend parses the malformed JSON and executes the injected payload or swaps the image for a phishing URL."
    WIKI_RECOMMENDATION = "Escape user-controlled strings before splicing into JSON (Strings.escapeJSON / custom _escape). Validate that token.symbol() is printable ASCII with bounded length. Prefer off-chain metadata with on-chain content hash over on-chain string assembly."

    _PRECONDITIONS = [{'contract.source_matches_regex': '.*'}, {'contract.has_function_matching': '(?i)(tokenURI|constructTokenURI|descriptor|renderURI|_renderURI)'}]
    _MATCH = [{'function.name_matches': '(?i)(tokenURI|constructTokenURI|_renderMetadata|_descriptor|_tokenDescriptor|getMetadata|contractURI)'}, {'function.body_contains_regex': '(?i)(abi\\.encodePacked|string\\.concat|string\\(abi\\.encodePacked).{0,400}(symbol|name|description|\\.symbol\\(\\)|\\.name\\(\\))'}, {'function.body_not_contains_regex': '(?i)(Base64|_escape|sanitize|_sanitize|Strings\\.escapeJSON|validateUTF8|_validSymbol|_onlyPrintable)'}, {'function.not_in_skip_list': True}, {'function.not_source_matches_regex': '(?i)\\b(mock|test|fixture)'}]

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
                info = [f, f" — token-uri-string-injection-no-sanitize: pattern matched. See WIKI for details."]
                results.append(self.generate_result(info))
        return results
