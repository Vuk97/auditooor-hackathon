"""
w69-governor-quorum-live-supply-snapshot-mismatch

Custom Solidity detector for governance snapshot mismatch:

1. The contract stores proposal snapshot state.
2. Voting reads past votes against that snapshot.
3. The quorum path still derives quorum from live totalSupply().

This is the "impossible quorum" drift class from the confirmed governance
corpus, narrowed to a production-shaped Governor surface rather than the older
graveyard placeholder detector.
"""

from __future__ import annotations

import re
import sys as _sys
from pathlib import Path as _Path

_sys.path.insert(0, str(_Path(__file__).resolve().parent.parent))
from _template_utils import is_vendored_or_test_contract

from slither.detectors.abstract_detector import (
    DETECTOR_INFO,
    AbstractDetector,
    DetectorClassification,
)
from slither.utils.output import Output


_PROPOSAL_SURFACE_RE = re.compile(r"(?i)\bproposal\w*\b")
_SNAPSHOT_SURFACE_RE = re.compile(r"(?i)(snapshot(Block|Id)?|proposalSnapshot|timepoint|clock\(\))")
_PAST_VOTE_SURFACE_RE = re.compile(r"(?i)(getPastVotes|getPriorVotes|checkpoints?)")
_QUORUM_FN_RE = re.compile(r"(?i)^_?quorum(_reached)?$")
_LIVE_SUPPLY_RE = re.compile(r"(?i)\b(totalSupply|IERC20Votes\([^)]*\)\.totalSupply)\s*\(")
_SNAPSHOTTED_SUPPLY_RE = re.compile(r"(?i)(getPastTotalSupply|getPastVotes|getPriorVotes|balanceOfAt)")


def _source_of(obj) -> str:
    try:
        return obj.source_mapping.content or ""
    except Exception:
        return ""


class W69GovernorQuorumLiveSupplySnapshotMismatch(AbstractDetector):
    ARGUMENT = "w69-governor-quorum-live-supply-snapshot-mismatch"
    HELP = "Governor quorum uses live totalSupply() even though voting power is snapshotted per proposal"
    IMPACT = DetectorClassification.HIGH
    CONFIDENCE = DetectorClassification.MEDIUM

    WIKI = "https://github.com/Vuk97/auditooor/blob/main/reference/patterns.dsl/glider-impossible-quorum.yaml"
    WIKI_TITLE = "Governor quorum computed from live supply instead of proposal snapshot"
    WIKI_DESCRIPTION = (
        "A governance contract snapshots proposal voting power with "
        "`getPastVotes(...)` or checkpoints, but its quorum path still derives "
        "the threshold from live `totalSupply()`. Mint, burn, rebase, or "
        "bridging changes after the snapshot can make quorum unreachable or "
        "artificially easy."
    )
    WIKI_EXPLOIT_SCENARIO = (
        "A proposal snapshots voting power at block N. After that block, supply "
        "expands sharply. Holders can still cast votes only against the "
        "snapshot, but quorum is now computed from the larger live supply, so "
        "the proposal can no longer reach quorum."
    )
    WIKI_RECOMMENDATION = (
        "Compute quorum from `getPastTotalSupply(proposal.snapshotBlock)` or an "
        "equivalent snapshotted total-supply source bound to the same proposal "
        "timepoint as voting power."
    )

    SUBMISSION_POSTURE = "NOT_SUBMIT_READY"
    COVERAGE_CLAIM = "detector_fixture_smoke_only"
    PROMOTION_ALLOWED = False

    def _detect(self) -> list[Output]:
        results: list[Output] = []

        for contract in self.contracts:
            if is_vendored_or_test_contract(contract):
                continue

            contract_source = "\n".join(
                _source_of(function)
                for function in getattr(contract, "functions_and_modifiers_declared", []) or []
            )
            if not _PROPOSAL_SURFACE_RE.search(contract_source):
                continue
            if not _SNAPSHOT_SURFACE_RE.search(contract_source):
                continue
            if not _PAST_VOTE_SURFACE_RE.search(contract_source):
                continue

            for function in getattr(contract, "functions_and_modifiers_declared", []) or []:
                name = getattr(function, "name", "") or ""
                if not _QUORUM_FN_RE.search(name):
                    continue

                source = _source_of(function)
                if not _LIVE_SUPPLY_RE.search(source):
                    continue
                if _SNAPSHOTTED_SUPPLY_RE.search(source):
                    continue

                info: DETECTOR_INFO = [
                    function,
                    " computes quorum from live totalSupply() while the contract "
                    "also exposes proposal snapshot voting via getPastVotes/checkpoints. "
                    "Use a proposal-bound past total-supply source instead.\n",
                ]
                results.append(self.generate_result(info))

        return results
