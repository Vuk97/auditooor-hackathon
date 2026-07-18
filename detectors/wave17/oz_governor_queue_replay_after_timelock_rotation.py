"""
oz-governor-queue-replay-after-timelock-rotation

Narrow fixture-smoke detector for Governor/TimelockControl-style contracts that
queue operations by proposal hash and expose a public timelock rotation path
without visibly cancelling or invalidating already queued operation ids.
"""

from __future__ import annotations

import re
import sys
from pathlib import Path as _Path

sys.path.insert(0, str(_Path(__file__).resolve().parent.parent))
from _template_utils import is_leaf_helper, is_vendored_or_test_contract

from slither.detectors.abstract_detector import (
    DETECTOR_INFO,
    AbstractDetector,
    DetectorClassification,
)
from slither.utils.output import Output


_CONTRACT_REPLAY_SURFACE_RE = re.compile(
    r"\b(?:GovernorTimelockControl|TimelockController|_timelockIds|"
    r"hashProposal|scheduleBatch|schedule\s*\()\b",
    re.IGNORECASE,
)
_TIMELOCK_IDS_RE = re.compile(r"\b_timelockIds\b")
_QUEUE_SCHEDULE_RE = re.compile(
    r"\b_timelockIds\s*\[[^\]]+\]\s*=|"
    r"\.\s*schedule(?:Batch)?\s*\(",
    re.IGNORECASE | re.DOTALL,
)
_HASH_PROPOSAL_NAME_RE = re.compile(r"^hashProposal$", re.IGNORECASE)
_PAYLOAD_HASH_RE = re.compile(
    r"keccak256\s*\(\s*abi\.encode\s*\([^)]*targets[^)]*values[^)]*"
    r"calldatas[^)]*descriptionHash",
    re.IGNORECASE | re.DOTALL,
)
_TIMELOCK_IN_HASH_RE = re.compile(r"\b(?:timelock|_timelock|newTimelock)\b", re.IGNORECASE)
_ROTATION_NAME_RE = re.compile(
    r"^(?:updateTimelock|setTimelock|rotateTimelock|changeTimelock)$",
    re.IGNORECASE,
)
_ROTATION_EFFECT_RE = re.compile(
    r"\b(?:_updateTimelock|_timelock\s*=|timelock\s*=|TimelockChange|"
    r"newTimelock)\b",
    re.IGNORECASE,
)
_QUEUE_INVALIDATION_RE = re.compile(
    r"\b(?:delete\s+_timelockIds|_timelockIds\s*\[[^\]]+\]\s*=\s*"
    r"(?:bytes32\s*\(\s*0\s*\)|0)|cancel\s*\(|_cancel\s*\(|"
    r"invalidate(?:Queued|Pending)?|clear(?:Queued|Pending)?|"
    r"migrate(?:Queued|Pending)?|timelockVersion|includeTimelockInProposalId|"
    r"pendingProposalIds|queuedProposalIds)\b",
    re.IGNORECASE | re.DOTALL,
)


def _source_of(obj) -> str:
    try:
        return obj.source_mapping.content or ""
    except Exception:
        return ""


def _rotation_scope_source(function) -> str:
    parts = [_source_of(function)]
    try:
        for internal in getattr(function, "internal_calls", []) or []:
            name = getattr(internal, "name", "") or ""
            if re.search(r"timelock", name, re.IGNORECASE):
                parts.append(_source_of(internal))
    except Exception:
        pass
    return "\n".join(part for part in parts if part)


def _hash_proposal_excludes_timelock(contract) -> bool:
    try:
        functions = getattr(contract, "functions_and_modifiers_declared", []) or []
        for function in functions:
            if not _HASH_PROPOSAL_NAME_RE.match(getattr(function, "name", "") or ""):
                continue
            source = _source_of(function)
            if _PAYLOAD_HASH_RE.search(source) and not _TIMELOCK_IN_HASH_RE.search(source):
                return True
    except Exception:
        pass
    return False


def _has_governor_queue_replay_surface(contract) -> bool:
    source = _source_of(contract)
    if not source or not _CONTRACT_REPLAY_SURFACE_RE.search(source):
        return False
    if not _TIMELOCK_IDS_RE.search(source):
        return False
    if not _QUEUE_SCHEDULE_RE.search(source):
        return False
    return _hash_proposal_excludes_timelock(contract)


class OzGovernorQueueReplayAfterTimelockRotation(AbstractDetector):
    ARGUMENT = "oz-governor-queue-replay-after-timelock-rotation"
    HELP = (
        "Governor-style timelock rotation leaves queued proposal operation ids "
        "valid across timelock changes"
    )
    IMPACT = DetectorClassification.HIGH
    CONFIDENCE = DetectorClassification.MEDIUM
    WIKI = (
        "https://github.com/Vuk97/auditooor/blob/main/reference/patterns.dsl/"
        "oz-governor-queue-replay-after-timelock-rotation.yaml"
    )
    WIKI_TITLE = "Governor timelock rotation does not invalidate queued proposals"
    WIKI_DESCRIPTION = (
        "Fixture-smoke/source-shape proof only. The detector flags contracts "
        "with OZ-style proposal hashes and `_timelockIds` queue state when a "
        "public timelock rotation entrypoint updates the timelock without "
        "visible cancellation, deletion, migration, or versioning of queued ids."
    )
    WIKI_EXPLOIT_SCENARIO = (
        "A proposal is queued against Timelock-A. Governance rotates the "
        "governor to Timelock-B while the old `_timelockIds` entry remains "
        "valid and proposal ids are still only payload-derived. A later queue "
        "or execute path can treat the same semantic proposal as live under the "
        "fresh timelock."
    )
    WIKI_RECOMMENDATION = (
        "When rotating the timelock, cancel or delete queued operation ids, "
        "migrate them atomically, or bind proposal ids to a timelock/version. "
        "Keep this row NOT_SUBMIT_READY until validated against a real corpus "
        "target with executable exploit evidence."
    )

    SUBMISSION_POSTURE = "NOT_SUBMIT_READY"
    COVERAGE_CLAIM = "detector_fixture_smoke_only"
    PROMOTION_ALLOWED = False

    def _detect(self) -> list[Output]:
        results: list[Output] = []

        for contract in self.contracts:
            if is_vendored_or_test_contract(contract):
                continue
            if not _has_governor_queue_replay_surface(contract):
                continue

            for function in contract.functions_and_modifiers_declared:
                if is_leaf_helper(function):
                    continue
                if getattr(function, "visibility", "") not in {"external", "public"}:
                    continue
                if not _ROTATION_NAME_RE.match(getattr(function, "name", "") or ""):
                    continue

                source = _rotation_scope_source(function)
                if not source:
                    continue
                if not _ROTATION_EFFECT_RE.search(source):
                    continue
                if _QUEUE_INVALIDATION_RE.search(source):
                    continue

                info: DETECTOR_INFO = [
                    function,
                    " rotates a Governor timelock while the contract keeps "
                    "payload-derived queued operation ids and no visible "
                    "queue invalidation/migration in the rotation path.\n",
                ]
                results.append(self.generate_result(info))

        return results
