"""
pausable-contract-which-exposed-whennotpaused-only-exposed-pause-thus

Manual graveyard repair for the generated Glider row. The original generated
detector was both import-broken and semantically unmoored from the row claim.

This repair stays intentionally narrow. It flags only the owned fixture-smoke
source shape where a contract:

1. exposes at least one public/external mutable entrypoint protected by
   `whenNotPaused` (or an equivalent modifier name),
2. exposes a public/external wrapper that pauses the contract, and
3. does not expose any public/external wrapper that unpauses it.

That is source-shape evidence only and remains `submission_posture:
NOT_SUBMIT_READY`.
"""

from __future__ import annotations

import re
import sys
from pathlib import Path as _Path

_DETECTORS_ROOT = _Path(__file__).resolve().parent.parent
if str(_DETECTORS_ROOT) not in sys.path:
    sys.path.insert(0, str(_DETECTORS_ROOT))

from _template_utils import is_vendored_or_test_contract

from slither.detectors.abstract_detector import AbstractDetector, DetectorClassification


class PausableContractWhichExposedWhennotpausedOnlyExposedPauseThus(AbstractDetector):
    ARGUMENT = "pausable-contract-which-exposed-whennotpaused-only-exposed-pause-thus"
    HELP = "Contract exposes pause and whenNotPaused entrypoints, but no external unpause path"
    IMPACT = DetectorClassification.MEDIUM
    CONFIDENCE = DetectorClassification.LOW
    WIKI = "https://github.com/Vuk97/auditooor/blob/main/reference/bug_patterns_observed.md"
    WIKI_TITLE = "Pausable contract exposes pause but not unpause"
    WIKI_DESCRIPTION = (
        "Flags the owned fixture-smoke source shape where a contract exposes a "
        "public/external pause wrapper and public/external mutable entrypoints "
        "guarded by `whenNotPaused`, but exposes no matching public/external "
        "unpause wrapper."
    )
    WIKI_EXPLOIT_SCENARIO = (
        "An admin or privileged operator calls the exposed pause wrapper during an "
        "incident. The contract's mutable user flows are protected by "
        "`whenNotPaused`, but the deployment exposes no corresponding public "
        "unpause path. The contract stays bricked until an upgrade or privileged "
        "manual intervention restores an unpause entrypoint."
    )
    WIKI_RECOMMENDATION = (
        "Expose a controlled public/external unpause wrapper wherever the "
        "contract exposes a public/external pause wrapper and mutable "
        "`whenNotPaused` entrypoints. This row is fixture-smoke/source-shape "
        "proof only and remains NOT_SUBMIT_READY."
    )

    _PAUSE_GUARD_NAMES = {
        "whennotpaused",
        "notpaused",
        "onlywhennotpaused",
        "whenactive",
        "onlywhenactive",
    }
    _PAUSE_GUARD_REGEX = re.compile(
        r"\b(whenNotPaused|notPaused|onlyWhenNotPaused|whenActive|onlyWhenActive)\b"
    )
    _PAUSE_CALL_REGEX = re.compile(r"\b_pause\s*\(")
    _UNPAUSE_CALL_REGEX = re.compile(r"\b_unpause\s*\(")
    _MUTABILITY_BLOCKLIST = {"view", "pure"}

    @classmethod
    def _function_source(cls, function) -> str:
        return function.source_mapping.content or ""

    @classmethod
    def _modifier_names(cls, function) -> set[str]:
        names: set[str] = set()
        for modifier in getattr(function, "modifiers", []) or []:
            name = (getattr(modifier, "name", "") or "").strip().lower()
            if name:
                names.add(name)
        return names

    @classmethod
    def _has_pause_guard(cls, function) -> bool:
        if cls._modifier_names(function) & cls._PAUSE_GUARD_NAMES:
            return True
        return bool(cls._PAUSE_GUARD_REGEX.search(cls._function_source(function)))

    @classmethod
    def _is_public_or_external(cls, function) -> bool:
        return function.visibility in {"public", "external"}

    @classmethod
    def _is_mutable_user_entrypoint(cls, function) -> bool:
        if not cls._is_public_or_external(function):
            return False
        if function.is_constructor:
            return False
        if getattr(function, "state_mutability", "") in cls._MUTABILITY_BLOCKLIST:
            return False
        return cls._has_pause_guard(function)

    @classmethod
    def _is_pause_wrapper(cls, function) -> bool:
        if not cls._is_public_or_external(function):
            return False
        return bool(cls._PAUSE_CALL_REGEX.search(cls._function_source(function)))

    @classmethod
    def _is_unpause_wrapper(cls, function) -> bool:
        if not cls._is_public_or_external(function):
            return False
        return bool(cls._UNPAUSE_CALL_REGEX.search(cls._function_source(function)))

    def _detect(self):
        results = []
        for contract in self.contracts:
            if is_vendored_or_test_contract(contract):
                continue

            guarded_entries = [
                function
                for function in contract.functions_and_modifiers_declared
                if self._is_mutable_user_entrypoint(function)
            ]
            if not guarded_entries:
                continue

            pause_wrappers = [
                function
                for function in contract.functions_and_modifiers_declared
                if self._is_pause_wrapper(function)
            ]
            if not pause_wrappers:
                continue

            has_unpause_wrapper = any(
                self._is_unpause_wrapper(function)
                for function in contract.functions_and_modifiers_declared
            )
            if has_unpause_wrapper:
                continue

            pause_function = pause_wrappers[0]
            guarded_names = ", ".join(sorted({function.name for function in guarded_entries if function.name}))
            info = [
                pause_function,
                " exposes `_pause()` publicly while mutable entrypoints guarded by `whenNotPaused` remain externally reachable",
                f" ({guarded_names}). ",
                "No public/external `_unpause()` wrapper is visible in the same contract. ",
                "This row is fixture-smoke/source-shape proof only and remains NOT_SUBMIT_READY.",
            ]
            results.append(self.generate_result(info))

        return results
