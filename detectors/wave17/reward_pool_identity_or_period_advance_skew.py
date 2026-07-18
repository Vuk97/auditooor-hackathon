"""
reward-pool-identity-or-period-advance-skew - manual detector.

Flags two source-backed rewards-distribution-skew shapes:
1. rewards keyed only by token pair while canonical pool identity has richer
   dimensions such as fee, tick spacing, hooks, or pool id.
2. failed or undersold auction close returns before advancing the period.

Source: fire6-rwrq-rewards-distribution-skew-8d88ac50e6c2.
Posture: NOT_SUBMIT_READY fixture-smoke capability only.
"""

from __future__ import annotations

import re
import sys
from pathlib import Path as _Path

sys.path.insert(0, str(_Path(__file__).resolve().parent.parent))
from _template_utils import is_leaf_helper, is_vendored_or_test_contract

from slither.detectors.abstract_detector import AbstractDetector, DetectorClassification


_REWARD_POOL_CONTEXT_RE = re.compile(
    r"(?is)(reward|rewards|emission|incentive).{0,160}"
    r"(PoolKey|token0|token1|currency0|currency1|pair|poolId|canonicalPool|registeredPool)"
)
_RICH_POOL_IDENTITY_RE = re.compile(
    r"(?is)(fee|tickSpacing|tick_spacing|hooks|hook|poolId|PoolId|fullPoolIdentity|"
    r"canonicalPool|registeredPool|whitelistedPool)"
)
_POOL_REWARD_NAME_RE = re.compile(
    r"(?i)(distributeRewards|emitRewards|creditRewardsForPool|rewardForPair|"
    r"updateRewardStream|recordReward|accumulateReward|claimPoolReward|claimRewards)"
)
_PAIR_KEY_RE = re.compile(
    r"(?is)(abi\.encode(?:Packed)?\s*\([^;]*(?:key\.)?(?:token0|currency0)"
    r"[^;]*(?:key\.)?(?:token1|currency1)|"
    r"(?:rewards?ByPair|rewards?PerPair|pairRewards|rewardPair|pairReward)"
    r"\s*\[|pair\s*=\s*keccak256\s*\()"
)
_REWARD_PAIR_LEDGER_RE = re.compile(
    r"(?is)(rewards?ByPair|rewards?PerPair|pairRewards|rewardPair|pairReward)"
)
_STRICT_POOL_IDENTITY_GUARD_RE = re.compile(
    r"(?is)(key\.fee|key\.tickSpacing|key\.tick_spacing|key\.hooks|key\.hook|"
    r"poolId|PoolId|fullPoolIdentity|canonicalPool|registeredPool|"
    r"whitelistedPool|isCanonicalPool|canonicalPoolForPair|registeredPoolForPair|"
    r"poolKey\s*\()"
)

_PERIOD_CONTEXT_RE = re.compile(
    r"(?is)(reward|rewards|emission|auction|period|epoch|round)"
)
_PERIOD_NAME_RE = re.compile(
    r"(?i)(close|finalize|resolveAuction|endAuction|settleAuction|closeAuction|finalizeAuction)"
)
_PERIOD_ADVANCE_RE = re.compile(
    r"(?is)\b(currentPeriod|rewardPeriod|period|epoch|round)\b\s*"
    r"(\+\+|\+=\s*1|=\s*\1\s*\+\s*1)"
)
_FAILURE_IF_RE = re.compile(r"(?is)\bif\s*\((?P<cond>[^)]*)\)\s*\{(?P<body>.*?)\}")
_FAILURE_WORD_RE = re.compile(
    r"(?is)(FAILED|Failed|failed|UNDERSOLD|Undersold|undersold|CANCELLED|Cancelled|"
    r"cancelled|totalRaised\s*<\s*minRaise|raised\s*<\s*min|amountRaised\s*<\s*min|"
    r"!\s*success|success\s*==\s*false)"
)

_TOKEN_RE = re.compile(
    r'"(?:[^"\\]|\\.)*"|'
    r"'(?:[^'\\]|\\.)*'|"
    r"//[^\n\r]*|"
    r"/\*.*?\*/",
    re.DOTALL,
)


def _source(obj) -> str:
    try:
        return obj.source_mapping.content or ""
    except Exception:
        return ""


def _strip_comments_and_strings(source: str) -> str:
    def replace_token(match: re.Match[str]) -> str:
        text = match.group(0)
        return "\n" * text.count("\n") if "\n" in text else " "

    return _TOKEN_RE.sub(replace_token, source or "")


def _is_public_entry(function) -> bool:
    name = str(getattr(function, "name", "") or "")
    if name.startswith("slither"):
        return False
    return getattr(function, "visibility", "") in {"external", "public"}


def _pool_identity_arm(contract_source: str, function) -> bool:
    if not _REWARD_POOL_CONTEXT_RE.search(contract_source):
        return False
    if not _RICH_POOL_IDENTITY_RE.search(contract_source):
        return False

    name = str(getattr(function, "name", "") or "")
    if not _POOL_REWARD_NAME_RE.search(name):
        return False

    fn_source = _strip_comments_and_strings(_source(function))
    if not _PAIR_KEY_RE.search(fn_source):
        return False
    if not _REWARD_PAIR_LEDGER_RE.search(fn_source):
        return False
    if _STRICT_POOL_IDENTITY_GUARD_RE.search(fn_source):
        return False
    return True


def _failed_branch_without_advance(function_source: str) -> bool:
    for match in _FAILURE_IF_RE.finditer(function_source):
        branch_text = f"{match.group('cond')}\n{match.group('body')}"
        if not _FAILURE_WORD_RE.search(branch_text):
            continue
        body = match.group("body")
        if not re.search(r"(?i)\breturn\s*;", body):
            continue
        if _PERIOD_ADVANCE_RE.search(body):
            continue
        return True
    return False


def _period_advance_arm(contract_source: str, function) -> bool:
    if not _PERIOD_CONTEXT_RE.search(contract_source):
        return False

    name = str(getattr(function, "name", "") or "")
    if not _PERIOD_NAME_RE.search(name):
        return False

    fn_source = _strip_comments_and_strings(_source(function))
    if not _PERIOD_ADVANCE_RE.search(fn_source):
        return False
    return _failed_branch_without_advance(fn_source)


class RewardPoolIdentityOrPeriodAdvanceSkew(AbstractDetector):
    ARGUMENT = "reward-pool-identity-or-period-advance-skew"
    HELP = (
        "NOT_SUBMIT_READY fixture-smoke detector: reward distribution keyed by "
        "incomplete pool identity or failed period close that does not advance."
    )
    IMPACT = DetectorClassification.HIGH
    CONFIDENCE = DetectorClassification.MEDIUM
    WIKI = (
        "https://github.com/Vuk97/auditooor/blob/main/reference/patterns.dsl/"
        "reward-pool-identity-or-period-advance-skew.yaml"
    )
    WIKI_TITLE = "Reward pool identity or period advance skew"
    WIKI_DESCRIPTION = (
        "Reward distributors must bind rewards to the canonical pool identity "
        "and must advance period or epoch metadata on every terminal close path."
    )
    WIKI_EXPLOIT_SCENARIO = (
        "A lookalike pool with the same listed tokens claims pair-keyed rewards, "
        "or a failed auction returns before currentPeriod advances and later "
        "reward periods remain stuck."
    )
    WIKI_RECOMMENDATION = (
        "Key rewards by canonical pool id or full PoolKey, and advance period "
        "or epoch counters on failed, undersold, and cancelled close branches."
    )

    def _detect(self):
        results = []
        for contract in self.contracts:
            if is_vendored_or_test_contract(contract):
                continue
            contract_source = _strip_comments_and_strings(_source(contract))
            for function in contract.functions_and_modifiers_declared:
                if is_leaf_helper(function):
                    continue
                if not _is_public_entry(function):
                    continue

                pool_identity_hit = _pool_identity_arm(contract_source, function)
                period_advance_hit = _period_advance_arm(contract_source, function)
                if not pool_identity_hit and not period_advance_hit:
                    continue

                if pool_identity_hit:
                    reason = "pair-keyed rewards omit canonical pool identity"
                else:
                    reason = "failed close path returns before period advance"
                info = [
                    function,
                    (
                        " - reward-pool-identity-or-period-advance-skew: "
                        f"{reason}. See WIKI for details."
                    ),
                ]
                results.append(self.generate_result(info))
        return results
