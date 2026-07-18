"""
rounded-up-limit-debit-down-payout - custom two-function detector.
Source: roadmap-slice-6-worker-bl-fund-loss-via-arithmetic
"""

import re
import sys
from pathlib import Path as _Path

sys.path.insert(0, str(_Path(__file__).resolve().parent.parent))
from _template_utils import is_vendored_or_test_contract  # noqa: E402

from slither.detectors.abstract_detector import AbstractDetector, DetectorClassification


_ENTRY_NAME_RE = re.compile(r"^(deposit|redeem|withdraw|mint|claim\w*|settle\w*)$", re.IGNORECASE)
_UP_VAR_RE = re.compile(r"\buint(?:128|256)\s+(?P<var>(?:assets|shares)Up)\s*=\s*[^;]*Rounding\.Up", re.DOTALL)
_DOWN_VAR_RE = re.compile(r"\buint(?:128|256)\s+(?P<var>(?:assets|shares)Down)\s*=\s*[^;]*Rounding\.Down", re.DOTALL)
_HELPER_CALL_RE = re.compile(r"\b(?P<helper>_process\w*)\s*\((?P<args>[^;]*)\)", re.DOTALL)
_STATE_DEBIT_TEMPLATE = r"\bstate\.\w+\s*=\s*state\.\w+\s*-\s*{var}\b"
_VALUE_MOVE_TEMPLATE = (
    r"\b(?:withdraw|transfer|safeTransfer|safeTransferFrom|unreserve|reserve|send|pay)\w*"
    r"\s*\([^;]*\b{var}\b"
)
_ROUNDING_GUARD_TEMPLATE = (
    r"(?:require\s*\(\s*{up}\s*==\s*{down}|"
    r"if\s*\(\s*{up}\s*!=\s*{down}\s*\)\s*revert|"
    r"if\s*\(\s*{down}\s*<\s*{up}\s*\)\s*revert)"
)


def _source(obj) -> str:
    try:
        return obj.source_mapping.content or ""
    except Exception:
        return ""


def _contains_rounding_guard(source: str, up_var: str, down_var: str) -> bool:
    guard_re = re.compile(
        _ROUNDING_GUARD_TEMPLATE.format(up=re.escape(up_var), down=re.escape(down_var)),
        re.IGNORECASE | re.DOTALL,
    )
    return bool(guard_re.search(source))


def _helper_uses_lossy_pair(helper_source: str, up_var: str, down_var: str) -> bool:
    if _contains_rounding_guard(helper_source, up_var, down_var):
        return False

    debit_re = re.compile(
        _STATE_DEBIT_TEMPLATE.format(var=re.escape(up_var)),
        re.IGNORECASE | re.DOTALL,
    )
    move_re = re.compile(
        _VALUE_MOVE_TEMPLATE.format(var=re.escape(down_var)),
        re.IGNORECASE | re.DOTALL,
    )
    fixed_debit_re = re.compile(
        _STATE_DEBIT_TEMPLATE.format(var=re.escape(down_var)),
        re.IGNORECASE | re.DOTALL,
    )
    return bool(debit_re.search(helper_source) and move_re.search(helper_source) and not fixed_debit_re.search(helper_source))


class RoundedUpLimitDebitDownPayout(AbstractDetector):
    ARGUMENT = "rounded-up-limit-debit-down-payout"
    HELP = (
        "Async vault claim/redeem path debits the user's limit with a rounded-up amount "
        "but pays or transfers only the rounded-down amount."
    )
    IMPACT = DetectorClassification.HIGH
    CONFIDENCE = DetectorClassification.MEDIUM
    WIKI = "https://github.com/Vuk97/auditooor/blob/main/reference/patterns.dsl/rounded-up-limit-debit-down-payout.yaml"
    WIKI_TITLE = "Rounded-up claim debit with rounded-down payout"
    WIKI_DESCRIPTION = (
        "A public async-vault entrypoint computes `assetsUp/assetsDown` or `sharesUp/sharesDown` "
        "from the same request and passes both to an internal processor. The processor subtracts "
        "the rounded-up value from the user's claim limit while the value-moving call uses the "
        "rounded-down value, silently losing the rounding delta."
    )
    WIKI_EXPLOIT_SCENARIO = (
        "A redeem request with fractional conversion decrements `state.maxWithdraw` by `assetsUp` "
        "but unreserves and transfers only `assetsDown`; the missing wei cannot be claimed."
    )
    WIKI_RECOMMENDATION = (
        "Debit and pay with the same amount, or reject lossy conversions with an explicit "
        "`assetsUp == assetsDown` / `sharesUp == sharesDown` guard."
    )

    def _detect(self):
        results = []
        for contract in self.contracts:
            if is_vendored_or_test_contract(contract):
                continue

            helpers = {
                function.name: _source(function)
                for function in getattr(contract, "functions_and_modifiers_declared", []) or []
                if (function.name or "").startswith("_process")
            }
            if not helpers:
                continue

            for function in getattr(contract, "functions_and_modifiers_declared", []) or []:
                visibility = getattr(function, "visibility", "") or ""
                if visibility not in ("external", "public"):
                    continue
                if not _ENTRY_NAME_RE.search(function.name or ""):
                    continue

                source = _source(function)
                up_match = _UP_VAR_RE.search(source)
                down_match = _DOWN_VAR_RE.search(source)
                if up_match is None or down_match is None:
                    continue

                up_var = up_match.group("var")
                down_var = down_match.group("var")
                if up_var[:6] != down_var[:6]:
                    continue
                if _contains_rounding_guard(source, up_var, down_var):
                    continue

                for call_match in _HELPER_CALL_RE.finditer(source):
                    helper_name = call_match.group("helper")
                    args = call_match.group("args")
                    if not re.search(rf"\b{re.escape(up_var)}\b", args):
                        continue
                    if not re.search(rf"\b{re.escape(down_var)}\b", args):
                        continue
                    helper_source = helpers.get(helper_name, "")
                    if not helper_source:
                        continue
                    if not _helper_uses_lossy_pair(helper_source, up_var, down_var):
                        continue

                    info = [
                        function,
                        (
                            " - rounded-up-limit-debit-down-payout: "
                            f"{helper_name} debits {up_var} but moves {down_var}."
                        ),
                    ]
                    results.append(self.generate_result(info))
                    break

        return results
