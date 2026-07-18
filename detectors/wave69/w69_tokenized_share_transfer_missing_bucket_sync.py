"""
w69-tokenized-share-transfer-missing-bucket-sync

Custom Solidity detector for tokenized-share systems that keep a second
share-accounting bucket outside the ERC20 balance map. The vulnerable shape is:

1. Deposit/stake/bond/mint lifecycle writes a bucket like
   `validatorBondShares`, `delegatedShares`, or `stakedShares`.
2. A later redeem/withdraw/unstake path consumes that bucket.
3. The contract exposes a local transfer hook (`_update`, `_transfer`,
   `_beforeTokenTransfer`, `transfer`, `transferFrom`) for tokenized shares.
4. That hook moves balances but does not update or reconcile the bucket.

Seed: cross-language lift from the Go ValidatorBondShares drift class where
tokenized bond shares can be transferred while the validator/user share bucket
remains stale before redemption.
"""

from __future__ import annotations

import re
import sys as _sys
from pathlib import Path as _Path

_sys.path.insert(0, str(_Path(__file__).resolve().parent.parent))
from _template_utils import is_leaf_helper, is_vendored_or_test_contract

from slither.detectors.abstract_detector import (
    DETECTOR_INFO,
    AbstractDetector,
    DetectorClassification,
)
from slither.core.solidity_types import MappingType
from slither.utils.output import Output


_HOOK_NAMES = frozenset({
    "_update",
    "_transfer",
    "_beforeTokenTransfer",
    "_afterTokenTransfer",
    "transfer",
    "transferFrom",
})

_ENTRYPOINT_RE = re.compile(
    r"(?i)^(deposit|stake|bond|delegate|mint|issue|wrap|lock|depositFor|stakeFor)"
)
_EXIT_RE = re.compile(
    r"(?i)^(redeem|withdraw|unstake|unbond|burn|claim|exit|settle|slash)"
)
_BUCKET_RE = re.compile(
    r"(?i)("
    r"validator.*shares|bond.*shares|delegat(?:ed|ion).*shares|"
    r"stake[dr]?.*shares|principal.*shares|account(?:ed|ing)?.*shares|"
    r"user.*shares|member.*shares|bucket.*shares|share.*bucket|"
    r"tracked.*shares|ledger.*shares|receipt.*shares"
    r")"
)
_TOTAL_RE = re.compile(
    r"(?i)(total.*shares|shares.*total|total.*bond|bond.*total|"
    r"total.*stake|stake.*total|total.*delegat|delegat.*total|"
    r"tracked.*total|account(?:ed|ing).*total)"
)
_IGNORE_VAR_RE = re.compile(
    r"(?i)^(_?balances?|balanceOf|_?allowances?|totalSupply|nonces?|decimals)$"
)
_BALANCE_SURFACE_RE = re.compile(
    r"(?i)(_balances\s*\[|balances\s*\[|balanceOf\s*\[|super\s*\.\s*_update\s*\(|"
    r"super\s*\.\s*_transfer\s*\(|emit\s+Transfer\b|allowance\s*\()"
)
_SYNC_CALL_RE = re.compile(
    r"(?i)(sync|reconcile|checkpoint|move|transfer|settle|update)"
    r"[A-Za-z0-9_]{0,24}(share|bond|stake|bucket|principal|delegat)"
)


def _source_of(obj) -> str:
    try:
        return obj.source_mapping.content or ""
    except Exception:
        return ""


def _iter_internal_calls(function):
    seen: set[int] = set()
    stack = list(getattr(function, "internal_calls", []) or [])
    while stack:
        callee = stack.pop()
        ident = id(callee)
        if ident in seen:
            continue
        seen.add(ident)
        yield callee
        stack.extend(getattr(callee, "internal_calls", []) or [])


def _collect_written_state(function) -> set[object]:
    written = set(getattr(function, "state_variables_written", []) or [])
    for callee in _iter_internal_calls(function):
        written.update(getattr(callee, "state_variables_written", []) or [])
    return written


def _collect_source(function) -> str:
    chunks = [_source_of(function)]
    for callee in _iter_internal_calls(function):
        chunks.append(_source_of(callee))
    return "\n".join(chunk for chunk in chunks if chunk)


class W69TokenizedShareTransferMissingBucketSync(AbstractDetector):
    ARGUMENT = "w69-tokenized-share-transfer-missing-bucket-sync"
    HELP = (
        "Tokenized share transfer updates ERC20 balances but not validator/user "
        "share buckets later used by redeem/withdraw accounting"
    )
    IMPACT = DetectorClassification.MEDIUM
    CONFIDENCE = DetectorClassification.MEDIUM

    WIKI = "https://github.com/Vuk97/auditooor/blob/main/reference/bug_patterns_observed.md"
    WIKI_TITLE = "Tokenized share transfer missing bucket sync"
    WIKI_DESCRIPTION = (
        "Some staking, validator-bond, and vault systems tokenize shares as an "
        "ERC20 or ERC20-like balance while keeping a second accounting bucket "
        "such as `validatorBondShares[user]`, `delegatedShares[user]`, or "
        "`userShares[pool][user]`. Deposit or bond writes both layers, but the "
        "share transfer hook updates only the token balance. Later redeem or "
        "unstake paths still trust the stale bucket, so transferred shares are "
        "not redeemable, or the wrong user/validator bucket is charged."
    )
    WIKI_EXPLOIT_SCENARIO = (
        "Alice bonds validator shares and receives tokenized receipts. The "
        "bonding path increments both `_balances[alice]` and "
        "`validatorBondShares[validator][alice]`. Alice transfers half her "
        "receipts to Bob. `_update(from,to,shares)` only moves `_balances`. "
        "When Bob later redeems, the redeem path checks "
        "`validatorBondShares[validator][bob]` and sees zero, so Bob cannot "
        "redeem the transferred shares until an admin/manual reconciliation."
    )
    WIKI_RECOMMENDATION = (
        "Whenever tokenized shares move, also move or reconcile every "
        "load-bearing bucket that redeem/withdraw logic trusts. Prefer a single "
        "internal helper like `_moveValidatorBondShares(from, to, amount)` or "
        "`_reconcileShareBuckets(from, to)` called from `_update`/`_transfer`."
    )

    SUBMISSION_POSTURE = "NOT_SUBMIT_READY"
    COVERAGE_CLAIM = "detector_fixture_smoke_only"
    PROMOTION_ALLOWED = False

    def _detect(self) -> list[Output]:
        results: list[Output] = []

        for contract in self.contracts:
            if is_vendored_or_test_contract(contract):
                continue

            state_vars = list(getattr(contract, "state_variables", []) or [])
            bucket_vars = []
            total_vars = []
            for sv in state_vars:
                name = getattr(sv, "name", "") or ""
                if not name or _IGNORE_VAR_RE.search(name):
                    continue
                if isinstance(sv.type, MappingType) and _BUCKET_RE.search(name):
                    bucket_vars.append(sv)
                    continue
                if _TOTAL_RE.search(name):
                    total_vars.append(sv)

            if not bucket_vars:
                continue

            bucket_set = set(bucket_vars)
            tracked_set = bucket_set | set(total_vars)

            lifecycle_entry = False
            lifecycle_exit = False
            hook_functions = []

            for function in getattr(contract, "functions_and_modifiers_declared", []) or []:
                if is_leaf_helper(function):
                    continue
                name = getattr(function, "name", "") or ""
                if not name:
                    continue
                source = _collect_source(function)
                writes = _collect_written_state(function)

                if _ENTRYPOINT_RE.search(name) and tracked_set.intersection(writes):
                    lifecycle_entry = True

                if _EXIT_RE.search(name):
                    if tracked_set.intersection(writes) or any(
                        (getattr(sv, "name", "") or "") in source for sv in tracked_set
                    ):
                        lifecycle_exit = True

                if name in _HOOK_NAMES:
                    hook_functions.append(function)

            if not lifecycle_entry or not lifecycle_exit or not hook_functions:
                continue

            for function in hook_functions:
                source = _collect_source(function)
                writes = _collect_written_state(function)
                if not _BALANCE_SURFACE_RE.search(source):
                    continue
                if tracked_set.intersection(writes):
                    continue
                if _SYNC_CALL_RE.search(source):
                    continue

                bucket_names = ", ".join(sorted((sv.name or "") for sv in bucket_vars[:3]))
                info: DETECTOR_INFO = [
                    function,
                    " updates token-transfer balance surface without writing any "
                    "tracked share bucket or share-total accounting used by "
                    "redeem/withdraw flows. Candidate buckets: ",
                    bucket_names,
                    ".\n",
                ]
                results.append(self.generate_result(info))

        return results
