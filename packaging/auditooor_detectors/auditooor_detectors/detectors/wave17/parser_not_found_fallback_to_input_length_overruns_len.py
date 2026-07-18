"""
parser-not-found-fallback-to-input-length-overruns-len — generated from reference/patterns.dsl/parser-not-found-fallback-to-input-length-overruns-len.yaml
DO NOT EDIT BY HAND. Regenerate via: python3 tools/pattern-compile.py parser-not-found-fallback-to-input-length-overruns-len.yaml
Source: lisa-mine-r99-case-06678-c4-ens-2023-04
"""

import sys
from pathlib import Path as _Path
sys.path.insert(0, str(_Path(__file__).resolve().parent.parent))
from _template_utils import is_vendored_or_test_contract, is_leaf_helper
from _predicate_engine import eval_preconditions, eval_function_match

from slither.detectors.abstract_detector import AbstractDetector, DetectorClassification


class ParserNotFoundFallbackToInputLengthOverrunsLen(AbstractDetector):
    ARGUMENT = "parser-not-found-fallback-to-input-length-overruns-len"
    HELP = "Key-value / record parser uses a sentinel `type(uint256).max` to mark 'separator not found', then falls back to `input.length` as the terminator instead of `offset + len`. The caller asked the parser to operate within a bounded window `[offset, offset+len)`, but on a missing terminator the parser si"
    IMPACT = DetectorClassification.MEDIUM
    CONFIDENCE = DetectorClassification.MEDIUM
    WIKI = "https://github.com/Vuk97/auditooor/blob/main/reference/patterns.dsl/parser-not-found-fallback-to-input-length-overruns-len.yaml"
    WIKI_TITLE = "Parser falls back to `input.length` on missing terminator, ignoring caller-supplied len"
    WIKI_DESCRIPTION = "Pattern fires on `readKeyValue`-style helpers that take `(bytes input, uint256 offset, uint256 len)` and search for a value-terminator inside `[offset, offset+len)`. When the terminator is not found, the bug shape is `if (terminator == type(uint256).max) terminator = input.length;` — the function then returns `input[separator+1 : input.length]` rather than `input[separator+1 : offset+len]`. The se"
    WIKI_EXPLOIT_SCENARIO = "ENS DNS resolver parses TXT records via `RecordParser.readKeyValue(rdata, offset, fieldLen)`. An attacker crafts a TXT record with a payload like `name=alice<no-space>maliciousField=hostile` and calls a higher-level resolver with `fieldLen` covering only the `name=alice` portion. With no space inside the asked window the parser falls back to `rdata.length`, returns `value = 'alice<no-space>malicio"
    WIKI_RECOMMENDATION = "On missing terminator, set `terminator = offset + len` so the parser respects the caller's window. Equivalent: declare `uint256 cap = offset + len; if (terminator == type(uint256).max || terminator > cap) terminator = cap;`. Add a fuzz test that randomises both `offset` and `len` and asserts `nextOf"

    _PRECONDITIONS = [{'contract.has_function_matching': 'readKeyValue|readField|parseRecord|parseField|parseKeyValue|nextToken|readNext'}]
    _MATCH = [{'function.kind': 'any'}, {'function.has_param_name_matching': '^(input|data|buffer|src|str)$|^(offset|start|pos)$|^(len|length|n|size)$'}, {'function.body_contains_regex': '\\b(terminator|sep|end|stop|delim)\\s*==\\s*type\\s*\\(\\s*uint256\\s*\\)\\s*\\.\\s*max'}, {'function.body_contains_regex': '\\b(terminator|sep|end|stop|delim)\\s*=\\s*[a-zA-Z_][a-zA-Z0-9_]*\\.length\\s*;'}, {'function.body_not_contains_regex': '\\b(terminator|sep|end|stop|delim)\\s*=\\s*offset\\s*\\+\\s*len\\b|\\b(terminator|sep|end|stop|delim)\\s*=\\s*[a-zA-Z_][a-zA-Z0-9_]*\\s*\\+\\s*[a-zA-Z_][a-zA-Z0-9_]*\\s*;'}, {'function.not_in_skip_list': True}, {'function.not_source_matches_regex': '(?i)\\b(mock|test|fixture)'}]

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
                info = [f, f" — parser-not-found-fallback-to-input-length-overruns-len: pattern matched. See WIKI for details."]
                results.append(self.generate_result(info))
        return results
