"""
stableswap-amp-zero-config-liveness

Hand-written cross-contract detector seed for StableSwap-style pools whose
factory/constructor path accepts amp=0 while invariant or swap math later
divides by an amp-derived denominator.
"""

from __future__ import annotations

import re

from slither.detectors.abstract_detector import AbstractDetector, DetectorClassification


_AMP_PARAM_RE = re.compile(r"\b(_?baseAmp|_?amp|amplification)\b", re.IGNORECASE)
_ONLY_UPPER_BOUND_RE = re.compile(
    r"(?:_?baseAmp|_?amp|amplification)\s*(?:>=|>)\s*MAX_AMP",
    re.IGNORECASE,
)
_ZERO_AMP_GUARD_RE = re.compile(
    r"((?:_?baseAmp|_?amp|amplification)\s*==\s*0|"
    r"0\s*==\s*(?:_?baseAmp|_?amp|amplification)|"
    r"(?:_?baseAmp|_?amp|amplification)\s*(?:<=|<)\s*0|"
    r"0\s*(?:>=|>)\s*(?:_?baseAmp|_?amp|amplification)|"
    r"require\s*\([^;]*(?:_?baseAmp|_?amp|amplification)[^;]*(?:>|>=|!=)\s*0)",
    re.IGNORECASE | re.DOTALL,
)
_AMP_MATH_RE = re.compile(
    r"(ampTimesCoins\s*=\s*[^;]*(?:amplification|_amplification|amp)|"
    r"AMP_PRECISION\s*/\s*ampTimesCoins|"
    r"/\s*\(\s*ampTimesCoins|"
    r"/\s*ampTimesCoins)",
    re.IGNORECASE,
)
_RECOVERY_FROM_ZERO_BLOCK_RE = re.compile(
    r"currentAmp\s*=\s*getCurrentAmp\s*\(\s*\)[\s\S]{0,900}"
    r"(scaledNextAmp\s*>\s*currentAmp\s*\*\s*MAX_AMP_MULTIPLIER|"
    r"currentAmp\s*\*\s*MAX_AMP_MULTIPLIER)",
    re.IGNORECASE,
)


class StableswapAmpZeroConfigLiveness(AbstractDetector):
    ARGUMENT = "stableswap-amp-zero-config-liveness"
    HELP = (
        "StableSwap amp constructor/config path rejects only MAX_AMP, allowing "
        "amp=0 while downstream invariant math divides by amp-derived values."
    )
    IMPACT = DetectorClassification.MEDIUM
    CONFIDENCE = DetectorClassification.MEDIUM

    WIKI = "https://github.com/Vuk97/auditooor/blob/main/reference/patterns.dsl/stableswap-amp-zero-config-liveness.yaml"
    WIKI_TITLE = "StableSwap amp=0 accepted by config but breaks pool liveness"
    WIKI_DESCRIPTION = (
        "StableSwap amplification is a math-domain parameter, not an arbitrary "
        "configuration knob. Accepting zero can make invariant/swap math divide "
        "by zero or make recovery ramps impossible after liquidity exists."
    )
    WIKI_EXPLOIT_SCENARIO = (
        "A public factory deploys a pool with baseAmp=0. Liquidity can be added, "
        "but swaps later reach amp-derived denominators and revert; ramp recovery "
        "from zero is blocked by multiplier checks that compare against currentAmp."
    )
    WIKI_RECOMMENDATION = (
        "Reject amp=0 in every factory, constructor, and initializer path before "
        "deployment or registration. Add a liveness invariant that any accepted "
        "factory config can execute a minimal swap after balanced liquidity."
    )

    def _all_contract_source(self) -> str:
        parts: list[str] = []
        for contract in self.contracts:
            try:
                parts.append(contract.source_mapping.content or "")
            except Exception:
                continue
        return "\n".join(parts)

    def _detect(self):
        results = []
        all_source = self._all_contract_source()
        if not _AMP_MATH_RE.search(all_source):
            return results

        for contract in self.contracts:
            for function in contract.functions_and_modifiers_declared:
                if str(getattr(function, "name", "")).startswith("slither"):
                    continue
                try:
                    body = function.source_mapping.content or ""
                except Exception:
                    body = ""
                if not _AMP_PARAM_RE.search(body):
                    continue
                if not _ONLY_UPPER_BOUND_RE.search(body):
                    continue
                if _ZERO_AMP_GUARD_RE.search(body):
                    continue
                info = [
                    function,
                    " accepts zero amplification while StableSwap math or ramp recovery depends on a non-zero amp domain",
                ]
                results.append(self.generate_result(info))

        # If the constructor path is not directly visible in a flattened scan,
        # still flag an unrecoverable ramp shape when zero can be currentAmp.
        if results:
            return results
        for contract in self.contracts:
            for function in contract.functions_and_modifiers_declared:
                if str(getattr(function, "name", "")).startswith("slither"):
                    continue
                try:
                    body = function.source_mapping.content or ""
                except Exception:
                    body = ""
                if _RECOVERY_FROM_ZERO_BLOCK_RE.search(body):
                    info = [
                        function,
                        " ramp recovery compares against currentAmp and should be paired with constructor/factory amp>0 validation",
                    ]
                    results.append(self.generate_result(info))
        return results
