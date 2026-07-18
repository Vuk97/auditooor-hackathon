"""
lack-of-user-access-control-in-stakev2 — high-signal fixture-smoke detector.

Source row: reference/patterns.dsl/lack-of-user-access-control-in-stakev2.yaml
Posture: NOT_SUBMIT_READY (detector_fixture_smoke_only)
"""

from pathlib import Path as _Path
import re
import sys

sys.path.insert(0, str(_Path(__file__).resolve().parent.parent))

from slither.detectors.abstract_detector import AbstractDetector, DetectorClassification

from _template_utils import is_vendored_or_test_contract


class LackOfUserAccessControlInStakev2(AbstractDetector):
    ARGUMENT = "lack-of-user-access-control-in-stakev2"
    HELP = "StakeV2-shaped manager mutator writes managers[_manager] without visible caller authorization."
    IMPACT = DetectorClassification.HIGH
    CONFIDENCE = DetectorClassification.MEDIUM
    WIKI = "https://github.com/Vuk97/auditooor/blob/main/reference/patterns.dsl/lack-of-user-access-control-in-stakev2.yaml"
    WIKI_TITLE = "Lack of user access control in StakeV2 manager mutators"
    WIKI_DESCRIPTION = (
        "Fixture-smoke/source-shape proof only. Flags addManager/removeManager-like "
        "entrypoints that mutate managers[_manager] without a caller-authorization "
        "modifier or msg.sender guard. NOT_SUBMIT_READY."
    )
    WIKI_EXPLOIT_SCENARIO = (
        "An arbitrary caller invokes addManager/removeManager and mutates the manager "
        "mapping because only target-state checks exist, with no caller auth."
    )
    WIKI_RECOMMENDATION = (
        "Gate manager mutators behind owner/role authorization and keep this row "
        "NOT_SUBMIT_READY until broader corpus validation."
    )

    _FUNCTION_NAME = re.compile(r"^(addManager|removeManager)$")
    _MANAGER_WRITE = re.compile(r"\bmanagers\s*\[[^\]]+\]\s*=")
    _AUTH_MODIFIER = re.compile(
        r"(?i)\b("
        r"only(owner|admin|manager|role|operator|user)"
        r"|owneronly|adminonly|manageronly|roleonly"
        r"|hasrole|accesscontrol"
        r"|auth|authorized|restricted|requires?auth"
        r")\b"
    )
    _CALLER_AUTH_GUARD = re.compile(
        r"(?is)\b(require|assert)\s*\([^;{}]*(msg\.sender|_msgSender\s*\(|tx\.origin)[^;{}]*"
        r"(owner|admin|govern|role|access|manager|authorized|operator)"
    )

    def _writes_managers_mapping(self, function) -> bool:
        for variable in getattr(function, "state_variables_written", []) or []:
            if getattr(variable, "name", "") == "managers":
                return True
        source = getattr(function.source_mapping, "content", "") or ""
        return bool(self._MANAGER_WRITE.search(source))

    def _has_auth_modifier(self, function) -> bool:
        for modifier in getattr(function, "modifiers", []) or []:
            name = getattr(modifier, "name", "") or str(modifier)
            if self._AUTH_MODIFIER.search(name):
                return True
        source = getattr(function.source_mapping, "content", "") or ""
        signature = source.split("{", 1)[0]
        return bool(self._AUTH_MODIFIER.search(signature))

    def _has_visible_caller_auth_guard(self, function) -> bool:
        source = getattr(function.source_mapping, "content", "") or ""
        if self._CALLER_AUTH_GUARD.search(source):
            return True
        for node in getattr(function, "nodes", []) or []:
            expr = getattr(node, "expression", None)
            if expr is None:
                continue
            if self._CALLER_AUTH_GUARD.search(str(expr)):
                return True
        return False

    def _detect(self):
        results = []
        for contract in self.contracts:
            if is_vendored_or_test_contract(contract):
                continue
            for function in contract.functions_and_modifiers_declared:
                if not self._FUNCTION_NAME.search(function.name):
                    continue
                if not self._writes_managers_mapping(function):
                    continue
                if self._has_auth_modifier(function):
                    continue
                if self._has_visible_caller_auth_guard(function):
                    continue
                info = [
                    function,
                    " writes managers[_manager] without visible caller authorization. "
                    "NOT_SUBMIT_READY: fixture-smoke/source-shape proof only.",
                ]
                results.append(self.generate_result(info))
        return results
