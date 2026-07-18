"""
bridge-batch-partial-state-or-domain-omission

Detector capability for bridge inbound processors that finalize a message
before running a per-command batch loop, then accept a partial false result
from try/catch instead of reverting or clearing the consumed message marker.
"""

from __future__ import annotations

import re
import sys
from pathlib import Path as _Path

sys.path.insert(0, str(_Path(__file__).resolve().parent.parent))
from _template_utils import is_vendored_or_test_contract

from slither.detectors.abstract_detector import (
    DETECTOR_INFO,
    AbstractDetector,
    DetectorClassification,
)
from slither.utils.output import Output


_BRIDGE_CONTEXT_RE = re.compile(
    r"\b(?:bridge|gateway|crossChain|cross[-_ ]?chain|InboundMessage|"
    r"OutboundMessage|message\.nonce|leafProof|headerProof|commitment|"
    r"dispatch|commands|nonce|proof)\b",
    re.IGNORECASE,
)
_MESSAGE_FINALIZE_RE = re.compile(
    r"(?:\.\s*inboundNonce\s*\.\s*set\s*\([^;{}]+\)"
    r"|\binboundNonce\s*\+\+"
    r"|\b(?:inboundNonce|processed|consumed|used|finalized|dispatched)\s*\[[^\]]+\]\s*=\s*true"
    r"|\b(?:processed|consumed|used|finalized|dispatched)\s*\.\s*set\s*\([^;{}]+\))",
    re.IGNORECASE | re.DOTALL,
)
_PROOF_CONTEXT_RE = re.compile(
    r"\b(?:leafProof|headerProof|proof|commitment|MerkleProof\s*\.\s*processProof|"
    r"_verifyCommitment|verifyCommitment|messageHash|leafHash|keccak256\s*\(\s*abi\s*\.\s*encode)\b",
    re.IGNORECASE,
)
_NON_ATOMIC_BATCH_LOOP_RE = re.compile(
    r"\bfor\s*\([^)]*\)\s*\{"
    r"(?=[\s\S]*?\btry\b)"
    r"(?=[\s\S]*?\bcatch\b)"
    r"(?=[\s\S]*?(?:return\s+false\s*;|continue\s*;|\w*success\w*\s*=\s*false))",
    re.IGNORECASE,
)
_COMMAND_CONTEXT_RE = re.compile(
    r"\b(?:commands?\s*\[|message\.commands|CommandKind|handle\w+|dispatch\w+)\b",
    re.IGNORECASE,
)
_CATCH_REVERT_RE = re.compile(
    r"\bcatch\s*(?:\([^)]*\))?\s*\{[^{}]*(?:revert\s*\(|assembly\s*\{[^{}]*revert)",
    re.IGNORECASE | re.DOTALL,
)
_SUCCESS_GUARD_RE = re.compile(
    r"(?:require\s*\(\s*\w*success\w*\s*[,)]"
    r"|if\s*\(\s*!\s*\w*success\w*\s*\)\s*(?:\{[^{}]*\brevert\b|\brevert\b)"
    r"|if\s*\(\s*\w*success\w*\s*==\s*false\s*\)\s*(?:\{[^{}]*\brevert\b|\brevert\b))",
    re.IGNORECASE | re.DOTALL,
)
_ROLLBACK_RE = re.compile(
    r"(?:delete\s+(?:\w+\.)?(?:inboundNonce|processed|consumed|used|finalized|dispatched)"
    r"|\b(?:inboundNonce|processed|consumed|used|finalized|dispatched)\s*\[[^\]]+\]\s*=\s*false"
    r"|\.\s*(?:unset|clear)\s*\([^;{}]*(?:nonce|message|dispatch|processed|consumed|used)[^;{}]*\))",
    re.IGNORECASE | re.DOTALL,
)
_DISPATCHISH_NAME_RE = re.compile(
    r"(?:dispatch|process|execute|handle).*(?:batch|command|message|payload)?",
    re.IGNORECASE,
)
_TOKEN_RE = re.compile(
    r'"(?:[^"\\]|\\.)*"|'
    r"'(?:[^'\\]|\\.)*'|"
    r"//[^\n\r]*|"
    r"/\*.*?\*/",
    re.DOTALL,
)


def _source_of(obj) -> str:
    try:
        return obj.source_mapping.content or ""
    except Exception:
        return ""


def _code_only(source: str) -> str:
    def replace_token(match: re.Match[str]) -> str:
        text = match.group(0)
        return "\n" * text.count("\n") if "\n" in text else " "

    return _TOKEN_RE.sub(replace_token, source or "")


def _is_non_atomic_batch_dispatcher(function) -> bool:
    source = _code_only(_source_of(function))
    if not source:
        return False
    name = getattr(function, "name", "") or ""
    if not _DISPATCHISH_NAME_RE.search(name) and not _COMMAND_CONTEXT_RE.search(source):
        return False
    if not _COMMAND_CONTEXT_RE.search(source):
        return False
    if not _NON_ATOMIC_BATCH_LOOP_RE.search(source):
        return False
    if _CATCH_REVERT_RE.search(source):
        return False
    return True


def _non_atomic_dispatcher_names(contract) -> set[str]:
    names: set[str] = set()
    for function in getattr(contract, "functions_and_modifiers_declared", []) or []:
        if _is_non_atomic_batch_dispatcher(function):
            name = getattr(function, "name", "") or ""
            if name:
                names.add(name)
    return names


def _dispatch_call_after_marker(source: str, marker_pos: int, names: set[str]) -> int | None:
    best: int | None = None
    for name in names:
        call_re = re.compile(r"\b" + re.escape(name) + r"\s*\(", re.IGNORECASE)
        match = call_re.search(source, marker_pos)
        if match is None:
            continue
        if best is None or match.start() < best:
            best = match.start()
    return best


def _has_unsafe_finalized_batch_submit(function, dispatcher_names: set[str]) -> bool:
    if not dispatcher_names:
        return False
    source = _code_only(_source_of(function))
    if not source:
        return False
    if not _BRIDGE_CONTEXT_RE.search(source):
        return False
    if not _PROOF_CONTEXT_RE.search(source):
        return False

    marker = _MESSAGE_FINALIZE_RE.search(source)
    if marker is None:
        return False

    dispatch_pos = _dispatch_call_after_marker(source, marker.end(), dispatcher_names)
    if dispatch_pos is None:
        return False

    tail = source[dispatch_pos:]
    if _SUCCESS_GUARD_RE.search(tail):
        return False
    if _ROLLBACK_RE.search(tail):
        return False
    return True


class BridgeBatchPartialStateOrDomainOmission(AbstractDetector):
    ARGUMENT = "bridge-batch-partial-state-or-domain-omission"
    HELP = (
        "Bridge inbound batch handler finalizes the message before a "
        "try/catch per-command dispatcher and accepts a partial false result "
        "instead of reverting or clearing the consumed marker"
    )
    IMPACT = DetectorClassification.HIGH
    CONFIDENCE = DetectorClassification.MEDIUM
    WIKI = (
        "https://github.com/Vuk97/auditooor/blob/main/reference/patterns.dsl/"
        "bridge-batch-partial-state-or-domain-omission.yaml"
    )
    WIKI_TITLE = "Bridge batch dispatch accepts partial state after message finalization"
    WIKI_DESCRIPTION = (
        "Cross-chain inbound messages need atomic, retryable, or isolated "
        "command semantics. This detector flags the unsafe middle ground: the "
        "submit path consumes a message marker before dispatch, while the "
        "batch dispatcher catches command failures and returns false or "
        "continues instead of reverting the whole message."
    )
    WIKI_EXPLOIT_SCENARIO = (
        "A batch message has two commands. Command one succeeds and mutates "
        "state. Command two reverts. The dispatcher catches the failure and "
        "returns false, but the submit path already consumed the message "
        "nonce and only emits the false result. The batch is left partially "
        "applied and cannot be retried with the same proof."
    )
    WIKI_RECOMMENDATION = (
        "For atomic batches, consume the message marker only after dispatch "
        "success or revert on failure. For retryable batches, clear the marker "
        "on failure. For isolated commands, give each command its own "
        "domain-scoped receipt and retry key."
    )

    SUBMISSION_POSTURE = "NOT_SUBMIT_READY"
    COVERAGE_CLAIM = "detector_fixture_smoke_only"
    PROMOTION_ALLOWED = False

    def _detect(self) -> list[Output]:
        results: list[Output] = []

        for contract in self.contracts:
            if is_vendored_or_test_contract(contract):
                continue
            if not _BRIDGE_CONTEXT_RE.search(_code_only(_source_of(contract))):
                continue

            dispatcher_names = _non_atomic_dispatcher_names(contract)
            if not dispatcher_names:
                continue

            for function in contract.functions_and_modifiers_declared:
                if _is_non_atomic_batch_dispatcher(function):
                    continue
                if not _has_unsafe_finalized_batch_submit(function, dispatcher_names):
                    continue

                sorted_dispatchers = ", ".join(sorted(dispatcher_names))
                info: DETECTOR_INFO = [
                    function,
                    " finalizes a bridge message before calling non-atomic "
                    f"batch dispatcher(s): {sorted_dispatchers}.\n",
                ]
                results.append(self.generate_result(info))

        return results
