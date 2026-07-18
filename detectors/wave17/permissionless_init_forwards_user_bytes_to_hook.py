"""
permissionless-init-forwards-user-bytes-to-hook

Fixture-smoke/source-shape detector for the owned row where a public or
external initialize-style entrypoint accepts `bytes hookData` from the caller
and forwards that same value into a hook `beforeInitialize`/`afterInitialize`
callback without a visible same-function caller guard.

Submission posture: NOT_SUBMIT_READY. This detector intentionally proves only
the checked-in fixture shape.
"""

from __future__ import annotations

import re
import sys
from pathlib import Path as _Path

sys.path.insert(0, str(_Path(__file__).resolve().parent.parent))
from _template_utils import is_leaf_helper, is_vendored_or_test_contract

from slither.detectors.abstract_detector import AbstractDetector, DetectorClassification


_CONTEXT_RE = re.compile(
    r"(?i)\b(?:beforeInitialize|afterInitialize|hookData|IHooks|hooks)\b"
)
_FUNCTION_NAME_RE = re.compile(
    r"(?i)^(?:initialize|initializePool|createPool|createAndInitialize)$"
)
_HOOKDATA_PARAM_RE = re.compile(r"(?i)\bbytes\s+(?:calldata|memory)\s+hookData\b")
_HOOK_CALLBACK_RE = re.compile(
    r"(?is)\b(?:hooks?\s*\.\s*)?(?:beforeInitialize|afterInitialize)"
    r"\s*\([^;{}]*\bhookData\b"
)
_AUTHZ_RE = re.compile(
    r"(?i)\b(?:onlyOwner|onlyRole|onlyFactory|onlyAdmin|requiresAuth|auth)\b"
    r"|require\s*\(\s*msg\.sender\s*==\s*(?:owner|admin|factory|deployer|creator)\b"
    r"|require\s*\(\s*_msgSender\s*\(\s*\)\s*==\s*(?:owner|admin|factory|deployer|creator)\b"
)


def _source(obj) -> str:
    try:
        return obj.source_mapping.content or ""
    except Exception:
        return ""


class PermissionlessInitForwardsUserBytesToHook(AbstractDetector):
    ARGUMENT = "permissionless-init-forwards-user-bytes-to-hook"
    HELP = (
        "NOT_SUBMIT_READY fixture-smoke/source-shape proof only: flags the "
        "owned initialize-style shape where user-supplied `hookData` is "
        "forwarded into a hook init callback without a visible caller guard."
    )
    IMPACT = DetectorClassification.MEDIUM
    CONFIDENCE = DetectorClassification.MEDIUM
    WIKI = (
        "https://github.com/Vuk97/auditooor/blob/main/reference/patterns.dsl/"
        "permissionless-init-forwards-user-bytes-to-hook.yaml"
    )
    WIKI_TITLE = "Permissionless initialize forwards caller bytes to hook init callback"
    WIKI_DESCRIPTION = (
        "Fixture-smoke/source-shape proof only: this row proves only the owned "
        "initialize-style entrypoint where a public/external initializer accepts "
        "`bytes hookData` from the caller and forwards that same variable into "
        "a hook `beforeInitialize(...)` or `afterInitialize(...)` callback "
        "without a visible same-function caller authorization guard. "
        "NOT_SUBMIT_READY."
    )
    WIKI_EXPLOIT_SCENARIO = (
        "A pool manager leaves `initialize(key, sqrtPriceX96, hookData)` "
        "permissionless and immediately calls `hooks.beforeInitialize(..., "
        "hookData)`. A searcher front-runs the intended deployer, seeds the "
        "hook with attacker-chosen bytes, and permanently initializes the pool "
        "under that configuration."
    )
    WIKI_RECOMMENDATION = (
        "Do not forward caller-supplied hook init bytes from a permissionless "
        "initializer. Gate the initializer or move hook configuration to a "
        "separate authorized path. Keep this row NOT_SUBMIT_READY until there "
        "is corpus-backed exploit evidence beyond the owned fixture pair."
    )

    SUBMISSION_POSTURE = "NOT_SUBMIT_READY"
    COVERAGE_CLAIM = "detector_fixture_smoke_only"
    PROMOTION_ALLOWED = False

    def _detect(self):
        results = []
        for contract in self.contracts:
            if is_vendored_or_test_contract(contract):
                continue

            contract_src = _source(contract)
            if not _CONTEXT_RE.search(contract_src):
                continue

            for function in contract.functions_and_modifiers_declared:
                if getattr(function, "visibility", "") not in {"external", "public"}:
                    continue
                if is_leaf_helper(function):
                    continue
                if not _FUNCTION_NAME_RE.search(function.name or ""):
                    continue

                function_src = _source(function)
                if not function_src:
                    continue
                if not _HOOKDATA_PARAM_RE.search(function_src):
                    continue
                if not _HOOK_CALLBACK_RE.search(function_src):
                    continue
                if _AUTHZ_RE.search(function_src):
                    continue

                info = [
                    function,
                    (
                        " — permissionless-init-forwards-user-bytes-to-hook: "
                        "initialize-style entrypoint forwards caller `hookData` "
                        "into a hook init callback with no visible same-"
                        "function caller guard. NOT_SUBMIT_READY: fixture-"
                        "smoke/source-shape proof only."
                    ),
                ]
                results.append(self.generate_result(info))
        return results
