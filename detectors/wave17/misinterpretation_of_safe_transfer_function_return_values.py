"""
misinterpretation-of-safe-transfer-function-return-values

Manual graveyard repair for a legacy Glider import. The generated detector was a
broken name-match scaffold with an invalid import root and no relation to the
actual safeTransfer claim.

This row closure stays intentionally narrow and NOT_SUBMIT_READY. It proves only
the owned fixture-smoke/source-shape case where a public or external function
treats `.safeTransfer(...)` or `.safeTransferFrom(...)` as a boolean status
value instead of using it as a revert-only helper call.
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


_COMMENT_RE = re.compile(r"//.*?$|/\*.*?\*/", re.MULTILINE | re.DOTALL)
_STRING_RE = re.compile(r'"(?:\\.|[^"\\])*"|\'(?:\\.|[^\'\\])*\'')
_SAFE_TRANSFER_CALL_RE = re.compile(r"\.\s*safeTransfer(?:From)?\s*\(", re.IGNORECASE)
_BOOL_CAPTURE_RE = re.compile(
    r"\bbool\s+([A-Za-z_][A-Za-z0-9_]*)\s*=\s*[^;{}]*\.\s*safeTransfer(?:From)?\s*\(",
    re.IGNORECASE,
)
_DIRECT_STATUS_USE_RE = re.compile(
    r"\b(?:require|assert|if)\s*\(\s*!?\s*[^;{}]*\.\s*safeTransfer(?:From)?\s*\(",
    re.IGNORECASE,
)
_DIRECT_RETURN_RE = re.compile(
    r"\breturn\s+[^;{}]*\.\s*safeTransfer(?:From)?\s*\(",
    re.IGNORECASE,
)


def _function_source(function) -> str:
    try:
        return function.source_mapping.content or ""
    except Exception:
        return ""


def _strip_comments_and_strings(text: str) -> str:
    without_comments = _COMMENT_RE.sub("", text)
    return _STRING_RE.sub('""', without_comments)


def _captured_status_name(source: str) -> str | None:
    for match in _BOOL_CAPTURE_RE.finditer(source):
        variable_name = match.group(1)
        if re.search(
            rf"\b(?:require|assert)\s*\(\s*!?\s*{re.escape(variable_name)}\b",
            source,
        ):
            return variable_name
        if re.search(rf"\bif\s*\(\s*!?\s*{re.escape(variable_name)}\b", source):
            return variable_name
        if re.search(rf"\breturn\s+{re.escape(variable_name)}\s*;", source):
            return variable_name
    return None


class MisinterpretationOfSafeTransferFunctionReturnValues(AbstractDetector):
    ARGUMENT = "misinterpretation-of-safe-transfer-function-return-values"
    HELP = (
        "safeTransfer-style helper result is treated as a bool status value "
        "instead of a revert-only helper call"
    )
    IMPACT = DetectorClassification.MEDIUM
    CONFIDENCE = DetectorClassification.LOW
    WIKI = "https://github.com/Vuk97/auditooor/blob/main/reference/bug_patterns_observed.md"
    WIKI_TITLE = "Misinterpretation of safe transfer function return values"
    WIKI_DESCRIPTION = (
        "Fixture-smoke/source-shape proof only: flags a public or external call "
        "site that branches on, requires, or returns the apparent result of a "
        "`.safeTransfer(...)` or `.safeTransferFrom(...)` helper. "
        "NOT_SUBMIT_READY."
    )
    WIKI_EXPLOIT_SCENARIO = (
        "A token-sweep path writes `bool ok = IERC20(token).safeTransfer(to, amount); "
        "require(ok, 'safe transfer failed');`. The integration treats "
        "`safeTransfer` as a status-returning primitive instead of a helper that "
        "must encode transfer failure by reverting."
    )
    WIKI_RECOMMENDATION = (
        "Use a revert-only safe-transfer helper and call it as a standalone "
        "statement. Keep this row NOT_SUBMIT_READY until evidence expands beyond "
        "the owned fixture pair."
    )

    def _detect(self):
        results = []
        for contract in self.contracts:
            if is_vendored_or_test_contract(contract):
                continue

            for function in contract.functions_and_modifiers_declared:
                if function.visibility not in {"public", "external"}:
                    continue

                source = _strip_comments_and_strings(_function_source(function))
                if not source or not _SAFE_TRANSFER_CALL_RE.search(source):
                    continue

                captured_status = _captured_status_name(source)
                if captured_status is None:
                    if not _DIRECT_STATUS_USE_RE.search(source) and not _DIRECT_RETURN_RE.search(source):
                        continue
                    captured_status = "safeTransfer result"

                info = [
                    function,
                    (
                        f" treats `{captured_status}` as a boolean status value for a "
                        "safeTransfer-style helper call. NOT_SUBMIT_READY: "
                        "fixture-smoke/source-shape proof only.\n"
                    ),
                ]
                results.append(self.generate_result(info))

        return results
