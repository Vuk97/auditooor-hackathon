"""
callback-before-accounting-finalized-cross-contract - custom Slither detector.

Flags a narrow cross-contract reentrancy shape:
  1. an external/public mutating function transfers control to a callback,
     hook, receiver, adapter, or safe token receiver;
  2. the function finalizes critical accounting state only after that callback;
  3. a sibling external/public function reads the same state, giving the
     callback a stale-state reentry surface;
  4. no reentrancy guard is active on the callback entrypoint.

NOT_SUBMIT_READY: this detector and its fixtures are smoke evidence only. Hits
need source review, exploitability analysis, and proof before filing.
"""

from __future__ import annotations

import re
import sys as _sys
from pathlib import Path as _Path

_sys.path.insert(0, str(_Path(__file__).resolve().parent.parent))
from _template_utils import is_leaf_helper, is_vendored_or_test_contract

from slither.detectors.abstract_detector import (
    AbstractDetector,
    DETECTOR_INFO,
    DetectorClassification,
)
from slither.utils.output import Output


_CALLBACK_CALL_RE = re.compile(
    r"(?ix)"
    r"(?:"
    r"\bI[A-Za-z0-9_]*(?:Callback|Hook|Receiver|Adapter)[A-Za-z0-9_]*\s*\([^)]*\)\s*"
    r"\.\s*[A-Za-z_][A-Za-z0-9_]*\s*\(|"
    r"\b(?:callback|hook|receiver|adapter)\s*\.\s*[A-Za-z_][A-Za-z0-9_]*\s*\(|"
    r"\b(?:callback|hook|receiver|adapter)\s*\.\s*call\s*(?:\{|\()|"
    r"\.\s*on[A-Za-z0-9_]*(?:Received|Callback|Liquidate|Repay|Settle|Exit|Transfer)\s*\(|"
    r"\b(?:_safeMint|safeMint|safeTransferFrom|safeTransfer)\s*\("
    r")"
)

_CRITICAL_STATE_RE = re.compile(
    r"(?i)"
    r"(accounting|balance|balances|share|shares|debt|borrow|reserve|"
    r"position|positions|status|state|finalized|finalised|settled|"
    r"processed|claim|claimed|credit|credits|nonce|nonces|remaining|"
    r"filled|owed|supply|assets|collateral|pending|withdraw|exit)"
)

_GUARD_RE = re.compile(
    r"(?i)"
    r"(nonReentrant|nonreentrant|ReentrancyGuard|reentrancyGuard|"
    r"noReentrancy|reentrancyLock|_reentrancyGuardEntered|"
    r"_status\s*=\s*_?ENTERED|locked\s*=\s*true|entered\s*=\s*true|"
    r"_entered\s*=\s*true)"
)


def _text(obj) -> str:
    try:
        return str(getattr(obj.source_mapping, "content", "") or "")
    except Exception:
        return ""


def _source_line(obj) -> int:
    try:
        lines = list(getattr(obj.source_mapping, "lines", []) or [])
        if lines:
            return int(lines[0])
    except Exception:
        pass
    return 0


def _state_names(values) -> set[str]:
    names: set[str] = set()
    for value in values or []:
        name = str(getattr(value, "name", "") or "")
        if name:
            names.add(name)
    return names


def _critical_writes(node) -> set[str]:
    return {
        name
        for name in _state_names(getattr(node, "state_variables_written", []))
        if _CRITICAL_STATE_RE.search(name)
    }


def _function_reads_state(function, state_name: str) -> bool:
    if state_name in _state_names(getattr(function, "state_variables_read", [])):
        return True
    return re.search(rf"\b{re.escape(state_name)}\b", _text(function)) is not None


def _has_effect_or_external_call(function) -> bool:
    if _state_names(getattr(function, "state_variables_written", [])):
        return True
    if list(getattr(function, "high_level_calls", []) or []):
        return True
    if list(getattr(function, "low_level_calls", []) or []):
        return True
    return False


def _is_external_public(function) -> bool:
    return getattr(function, "visibility", "") in {"external", "public"}


def _guarded(function, callback_node) -> bool:
    modifier_names = " ".join(
        str(getattr(modifier, "name", "") or "") for modifier in (getattr(function, "modifiers", []) or [])
    )
    if _GUARD_RE.search(modifier_names):
        return True

    callback_line = _source_line(callback_node)
    prefix_lines: list[str] = []
    for node in getattr(function, "nodes", []) or []:
        node_line = _source_line(node)
        if callback_line and node_line and node_line >= callback_line:
            break
        prefix_lines.append(_text(node))
    function_header = _text(function).split("{", 1)[0]
    return _GUARD_RE.search(function_header + "\n" + "\n".join(prefix_lines)) is not None


def _sibling_reader(contract, function, state_names: set[str]):
    for other in getattr(contract, "functions_and_modifiers_declared", []) or []:
        if other is function:
            continue
        if getattr(other, "is_constructor", False):
            continue
        if not _is_external_public(other):
            continue
        if getattr(other, "view", False) or getattr(other, "pure", False):
            continue
        if is_leaf_helper(other):
            continue
        if not _has_effect_or_external_call(other):
            continue
        if any(_function_reads_state(other, state_name) for state_name in state_names):
            return other
    return None


class CallbackBeforeAccountingFinalizedCrossContract(AbstractDetector):
    ARGUMENT = "callback-before-accounting-finalized-cross-contract"
    HELP = (
        "Callback or safe receiver control transfer occurs before accounting "
        "finalization that a sibling entrypoint also reads."
    )
    IMPACT = DetectorClassification.HIGH
    CONFIDENCE = DetectorClassification.MEDIUM
    WIKI = (
        "https://github.com/Vuk97/auditooor/blob/main/reference/patterns.dsl/"
        "callback-before-accounting-finalized-cross-contract.yaml"
    )
    WIKI_TITLE = "Callback before accounting finalization enables stale-state reentrancy"
    WIKI_DESCRIPTION = (
        "The detector looks for an external/public function that calls a "
        "callback, hook, receiver, adapter, or safe token receiver before "
        "writing critical accounting state. It only reports when a sibling "
        "external/public function reads the same state, because that sibling "
        "entrypoint is the cross-contract reentry surface."
    )
    WIKI_EXPLOIT_SCENARIO = (
        "A withdrawal request validates a balance and calls a user hook before "
        "subtracting the balance and marking the request finalized. During the "
        "hook, the attacker reenters a settlement function that still reads the "
        "request as unfinalized and the balance as available."
    )
    WIKI_RECOMMENDATION = (
        "Finalize accounting before the callback, or apply a shared "
        "nonReentrant lock or per-position in-flight sentinel across every "
        "sibling entrypoint that reads the same state."
    )

    def _detect(self) -> list[Output]:
        results: list[Output] = []

        for contract in self.contracts:
            if is_vendored_or_test_contract(contract):
                continue

            for function in contract.functions_and_modifiers_declared:
                if getattr(function, "is_constructor", False):
                    continue
                if not _is_external_public(function):
                    continue
                if getattr(function, "view", False) or getattr(function, "pure", False):
                    continue
                if is_leaf_helper(function):
                    continue

                nodes = list(getattr(function, "nodes", []) or [])
                callback_nodes = [
                    node
                    for node in nodes
                    if list(getattr(node, "irs", []) or []) and _CALLBACK_CALL_RE.search(_text(node))
                ]
                if not callback_nodes:
                    continue

                for callback_node in callback_nodes:
                    if _guarded(function, callback_node):
                        continue

                    post_write_nodes = [
                        node
                        for node in nodes
                        if getattr(node, "node_id", -1) > getattr(callback_node, "node_id", -1)
                        and _critical_writes(node)
                    ]
                    if not post_write_nodes:
                        continue

                    state_names: set[str] = set()
                    for node in post_write_nodes:
                        state_names.update(_critical_writes(node))

                    sibling = _sibling_reader(contract, function, state_names)
                    if sibling is None:
                        continue

                    first_write = post_write_nodes[0]
                    info: DETECTOR_INFO = [
                        function,
                        " calls back at ",
                        callback_node,
                        " before finalizing accounting state at ",
                        first_write,
                        "; sibling entrypoint ",
                        sibling,
                        " reads the same state, creating a cross-contract stale-state reentry window.\n",
                    ]
                    results.append(self.generate_result(info))
                    break

        return results
