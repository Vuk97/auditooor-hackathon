"""
hyperevm-precompile-staticcall-no-length-check — generated from reference/patterns.dsl/hyperevm-precompile-staticcall-no-length-check.yaml
DO NOT EDIT BY HAND. Regenerate via: python3 tools/pattern-compile.py hyperevm-precompile-staticcall-no-length-check.yaml
Source: monetrix-c4-2026-04-capability-gap
"""

import sys
from pathlib import Path as _Path
sys.path.insert(0, str(_Path(__file__).resolve().parent.parent))
from _template_utils import is_vendored_or_test_contract, is_leaf_helper
from _predicate_engine import eval_preconditions, eval_function_match

from slither.detectors.abstract_detector import AbstractDetector, DetectorClassification


class HyperevmPrecompileStaticcallNoLengthCheck(AbstractDetector):
    ARGUMENT = "hyperevm-precompile-staticcall-no-length-check"
    HELP = "HyperCore precompile read does not assert a minimum return-data length before `abi.decode`. A short / empty response from a transient L1 outage or unrecognized request silently decodes to zero (or reverts mid-decode), leaving the protocol fail-open on backing / oracle / balance reads."
    IMPACT = DetectorClassification.HIGH
    CONFIDENCE = DetectorClassification.MEDIUM
    WIKI = "https://github.com/Vuk97/auditooor/blob/main/reference/patterns.dsl/hyperevm-precompile-staticcall-no-length-check.yaml"
    WIKI_TITLE = "HyperCore precompile staticcall result decoded without length check (fail-open)"
    WIKI_DESCRIPTION = "Hyperliquid's HyperEVM exposes L1 state through a fixed bank of read precompiles at 0x800-0x811. They are called via `(bool ok, bytes memory res) = ADDR.staticcall(abi.encode(args))` and return packed encodings of the underlying L1 struct. Unlike normal contract calls, an unsupported request, an indexer lag spike, or a malformed argument can return `(ok=true, res=\"\")` — empty bytes with success."
    WIKI_EXPLOIT_SCENARIO = "Lending protocol on HyperEVM reads collateral notional via `oraclePx(perpIdx)` (precompile 0x807). Implementation is `(bool ok, bytes memory res) = ORACLE.staticcall(abi.encode(perpIdx)); price = abi.decode(res, (uint64));` — no length check. A transient L1 outage causes the precompile to return `(true, \"\")` for ~30 seconds. During that window: (1) every `oraclePx` call returns 0; (2) collateral"
    WIKI_RECOMMENDATION = "Every HyperCore precompile read MUST gate the decode on a length floor matching the expected abi-encoded width: `require(ok && res.length >= 32, \"oracle read failed\")` for a single uint64; `>= 96` for `(uint64, uint64, uint64)` triple (SpotBalance); `>= 64` for `(uint64, uint64)` pair (VaultEquity"

    _PRECONDITIONS = [{'contract.source_matches_regex': '0x0?(?:000000000000000000000000000000000000)0?80[0-9a-fA-F]|PRECOMPILE_SPOT_BALANCE|PRECOMPILE_VAULT_EQUITY|PRECOMPILE_ORACLE_PX|PRECOMPILE_SPOT_PX|PRECOMPILE_PERP_ASSET_INFO|PRECOMPILE_TOKEN_INFO|PRECOMPILE_ACCOUNT_MARGIN|PRECOMPILE_SUPPLIED_BALANCE|HyperCoreConstants|hyperliquid|spotBalance|vaultEquity|oraclePx'}]
    _MATCH = [{'function.kind': 'any'}, {'function.body_contains_regex': '0x0000000000000000000000000000000000000800|0x0000000000000000000000000000000000000801|0x0000000000000000000000000000000000000802|0x0000000000000000000000000000000000000807|0x0000000000000000000000000000000000000808|0x000000000000000000000000000000000000080a|0x000000000000000000000000000000000000080A|0x000000000000000000000000000000000000080c|0x000000000000000000000000000000000000080C|0x000000000000000000000000000000000000080f|0x000000000000000000000000000000000000080F|0x0000000000000000000000000000000000000811|PRECOMPILE_(SPOT_BALANCE|VAULT_EQUITY|ORACLE_PX|SPOT_PX|PERP_ASSET_INFO|TOKEN_INFO|ACCOUNT_MARGIN|SUPPLIED_BALANCE|POSITION)'}, {'function.body_contains_regex': '\\.staticcall\\s*\\('}, {'function.body_contains_regex': 'abi\\.decode\\s*\\('}, {'function.body_not_contains_regex': 'res\\.length\\s*>=|result\\.length\\s*>=|data\\.length\\s*>=|ret\\.length\\s*>=|out\\.length\\s*>=|response\\.length\\s*>=|returndata\\.length\\s*>=|require\\s*\\(\\s*[a-zA-Z_]+\\.length\\s*>=|require\\s*\\(\\s*ok\\s*&&\\s*[a-zA-Z_]+\\.length'}, {'function.not_in_skip_list': True}, {'function.not_leaf_helper': True}, {'function.not_source_matches_regex': '(?i)\\b(mock|test|fixture)'}]

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
                info = [f, f" — hyperevm-precompile-staticcall-no-length-check: pattern matched. See WIKI for details."]
                results.append(self.generate_result(info))
        return results
