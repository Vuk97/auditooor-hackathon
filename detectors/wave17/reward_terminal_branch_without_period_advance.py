"""
reward-terminal-branch-without-period-advance

Flags reward, emission, and auction finalizers where a terminal failure branch
returns or reverts before advancing the period or epoch counter. This is a
same-class recall lift for rewards-distribution-skew misses such as failed or
undersold auction closes that leave the next reward period blocked.

Posture: NOT_SUBMIT_READY detector fixture smoke only.
"""

from __future__ import annotations

import re
import sys
from pathlib import Path as _Path

sys.path.insert(0, str(_Path(__file__).resolve().parent.parent))
from _predicate_engine import _source_without_comments_and_strings
from _template_utils import is_leaf_helper, is_vendored_or_test_contract

from slither.detectors.abstract_detector import AbstractDetector, DetectorClassification


_CONTEXT_RE = re.compile(
    r"\b(reward\w*|emission\w*|incentive\w*|auction\w*|gauge\w*|"
    r"period\w*|epoch\w*|round\w*)\b",
    re.IGNORECASE,
)
_FINALIZER_NAME_RE = re.compile(
    r"(?i)^(finalize|close|settle|end|resolve|rollover|advance|distribute)"
    r"\w*(Auction|Period|Epoch|Round|Rewards?|Emission)?\w*$"
)
_PERIOD_ADVANCE_RE = re.compile(
    r"\b(currentPeriod|rewardPeriod|period|periodIndex|auctionId|epoch|round)"
    r"\b\s*(\+\+|\+=\s*1|=\s*\1\s*\+\s*1|=\s*\1\s*\+\s*ONE)",
    re.IGNORECASE,
)
_PERIOD_ADVANCE_CALL_RE = re.compile(
    r"\b(_?advancePeriod|_?advanceEpoch|_?advanceRound|_?rollEpoch|"
    r"_?rollPeriod|_?startNextPeriod|_?startNextEpoch)\s*\(",
    re.IGNORECASE,
)
_IF_BLOCK_RE = re.compile(r"\bif\s*\((?P<cond>[^)]*)\)\s*\{(?P<body>.*?)\}", re.DOTALL)
_TERMINAL_RE = re.compile(r"\b(return\s*;|revert\b)", re.IGNORECASE)
_FAILURE_BRANCH_RE = re.compile(
    r"(?i)("
    r"FAILED|FAILURE|UNDERSOLD|NOT_FILLED|CANCELLED|EXPIRED|"
    r"!\s*success|success\s*==\s*false|"
    r"bidCount\s*==\s*0|bids?\.length\s*==\s*0|"
    r"totalRaised\s*<\s*min|amountRaised\s*<\s*min|raised\s*<\s*min|"
    r"sold\s*==\s*0|filled\s*==\s*0|winningBid\s*==\s*0|"
    r"clearingPrice\s*==\s*0"
    r")"
)
_SKIP_SOURCE_RE = re.compile(r"\b(mock|test|fixture)\b", re.IGNORECASE)


def _source(obj) -> str:
    try:
        return obj.source_mapping.content or ""
    except Exception:
        return ""


def _body_only(source: str) -> str:
    start = source.find("{")
    end = source.rfind("}")
    if start == -1:
        return source
    if end == -1 or end <= start:
        return source[start + 1 :]
    return source[start + 1 : end]


def _is_public_entry(function) -> bool:
    if str(getattr(function, "name", "") or "").startswith("slither"):
        return False
    return getattr(function, "visibility", "") in {"external", "public"}


def _has_period_advance(source: str) -> bool:
    return bool(_PERIOD_ADVANCE_RE.search(source) or _PERIOD_ADVANCE_CALL_RE.search(source))


def _terminal_failure_branch_without_advance(source: str) -> bool:
    for match in _IF_BLOCK_RE.finditer(source):
        cond = match.group("cond") or ""
        body = match.group("body") or ""
        branch_text = f"{cond}\n{body}"
        if not _FAILURE_BRANCH_RE.search(branch_text):
            continue
        if not _TERMINAL_RE.search(body):
            continue
        if _has_period_advance(body):
            continue
        return True
    return False


class RewardTerminalBranchWithoutPeriodAdvance(AbstractDetector):
    ARGUMENT = "reward-terminal-branch-without-period-advance"
    HELP = (
        "Reward, emission, or auction finalizer has a failed terminal branch "
        "that exits before advancing the period or epoch counter."
    )
    IMPACT = DetectorClassification.HIGH
    CONFIDENCE = DetectorClassification.MEDIUM
    WIKI = "https://github.com/Vuk97/auditooor"
    WIKI_TITLE = "Terminal reward period branch does not advance period"
    WIKI_DESCRIPTION = (
        "Reward and auction systems that sequence distributions by period or "
        "epoch must advance that counter on every terminal outcome. A failed, "
        "undersold, cancelled, or empty terminal branch that returns before "
        "the counter advances can stall later reward periods or let one period "
        "consume accounting intended for the next period."
    )
    WIKI_EXPLOIT_SCENARIO = (
        "An auction or reward period closes with zero bids or an undersold "
        "raise. The finalizer emits the failure path and returns before "
        "currentPeriod increments. Future auctions or reward emissions still "
        "see the old period and cannot progress cleanly."
    )
    WIKI_RECOMMENDATION = (
        "Advance the period or epoch counter on every terminal outcome before "
        "returning, or centralize finalization through one helper that always "
        "rolls the period regardless of success or failure."
    )

    _INCLUDE_LEAF_HELPERS = False
    _INVERSE_CEI = False

    def _detect(self):
        results = []
        for contract in self.contracts:
            if is_vendored_or_test_contract(contract):
                continue
            contract_source = _source_without_comments_and_strings(_source(contract))
            if not _CONTEXT_RE.search(contract_source):
                continue

            for function in contract.functions_and_modifiers_declared:
                if not self._INCLUDE_LEAF_HELPERS and is_leaf_helper(function):
                    continue
                if not _is_public_entry(function):
                    continue
                name = str(getattr(function, "name", "") or "")
                if not _FINALIZER_NAME_RE.search(name):
                    continue

                raw_source = _source(function)
                if _SKIP_SOURCE_RE.search(raw_source):
                    continue
                source = _source_without_comments_and_strings(_body_only(raw_source))
                if not _has_period_advance(source):
                    continue
                if not _terminal_failure_branch_without_advance(source):
                    continue

                info = [
                    function,
                    (
                        " - reward-terminal-branch-without-period-advance: "
                        "failed terminal branch exits before period advance."
                    ),
                ]
                results.append(self.generate_result(info))
        return results
