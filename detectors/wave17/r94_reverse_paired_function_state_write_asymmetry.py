"""
r94-reverse-paired-function-state-write-asymmetry

Fixture-smoke detector for same-stem lifecycle pairs where the add/grant/enable
side writes more storage slots than the remove/revoke/disable counterpart.

This is the Solidity sibling of detectors/rust_wave1/
paired_function_state_write_asymmetry.py and intentionally keeps the same
same-stem pairing rule to avoid cross-pair false positives.
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


_PAIR_PREFIXES: tuple[tuple[str, str], ...] = (
    ("add", "remove"),
    ("enable", "disable"),
    ("lock", "unlock"),
    ("register", "deregister"),
    ("grant", "revoke"),
    ("mint", "burn"),
)

_PAIR_SURFACE_RE = re.compile(
    r"\bfunction\s+(?:add|remove|grant|revoke|enable|disable|lock|unlock|"
    r"register|deregister|mint|burn)[A-Z_][A-Za-z0-9_]*\b"
)
_WRITE_OP_RE = r"(?:=|\+=|-=|\*=|/=|%=|&=|\|=|\^=)"
_METHOD_WRITE_RE = re.compile(r"\.\s*(?:push|pop|add|remove|insert|erase|clear|set)\s*\(")


def _source_of(obj) -> str:
    try:
        return obj.source_mapping.content or ""
    except Exception:
        return ""


def _candidate_name_pair(name: str) -> tuple[str, str] | None:
    for positive_prefix, negative_prefix in _PAIR_PREFIXES:
        if not name.startswith(positive_prefix):
            continue
        stem = name[len(positive_prefix):]
        if not stem or (not stem[0].isupper() and stem[0] != "_"):
            continue
        return name, f"{negative_prefix}{stem}"
    return None


def _state_var_names(contract) -> list[str]:
    names: list[str] = []
    for variable in (
        getattr(contract, "state_variables", None)
        or getattr(contract, "state_variables_declared", None)
        or []
    ):
        name = getattr(variable, "name", "") or ""
        if name:
            names.append(name)
    # Longer names first so a short name cannot pre-empt a longer sibling
    # when both appear in the same source line.
    return sorted(set(names), key=len, reverse=True)


def _touches_state_var(source: str, variable_name: str) -> bool:
    escaped = re.escape(variable_name)
    patterns = (
        rf"\bdelete\s+{escaped}\b(?:\s*\[[^\]]+\])*",
        rf"\b{escaped}\b(?:\s*\[[^\]]+\])+\s*{_WRITE_OP_RE}",
        rf"\b{escaped}\b\s*{_WRITE_OP_RE}",
        rf"(?:\+\+|--)\s*\b{escaped}\b",
        rf"\b{escaped}\b\s*(?:\+\+|--)",
        rf"\b{escaped}\b\s*\.\s*(?:push|pop|add|remove|insert|erase|clear|set)\s*\(",
    )
    return any(re.search(pattern, source) for pattern in patterns)


def _written_slots(function, contract) -> set[str]:
    source = _source_of(function)
    if not source or not _METHOD_WRITE_RE.search(source) and "=" not in source and "delete" not in source:
        return set()

    written: set[str] = set()
    for variable_name in _state_var_names(contract):
        if _touches_state_var(source, variable_name):
            written.add(variable_name)
    return written


def _has_pair_surface(contract) -> bool:
    return bool(_PAIR_SURFACE_RE.search(_source_of(contract)))


class R94ReversePairedFunctionStateWriteAsymmetry(AbstractDetector):
    ARGUMENT = "r94-reverse-paired-function-state-write-asymmetry"
    HELP = (
        "NOT_SUBMIT_READY detector-fixture-smoke-only: same-stem add/grant/"
        "enable functions write storage slots that the remove/revoke/disable "
        "counterpart never clears."
    )
    IMPACT = DetectorClassification.MEDIUM
    CONFIDENCE = DetectorClassification.LOW
    WIKI = (
        "https://github.com/Vuk97/auditooor/blob/main/reference/patterns.dsl/"
        "r94-reverse-paired-function-state-write-asymmetry.yaml"
    )
    WIKI_TITLE = "Paired add/remove functions write asymmetric storage slots"
    WIKI_DESCRIPTION = (
        "Detector-fixture-smoke-only. NOT_SUBMIT_READY. This row proves the "
        "owned same-stem lifecycle shape where `add*` / `grant*` / `enable*` "
        "writes a mapping, index, or array slot that `remove*` / `revoke*` / "
        "`disable*` never unwinds."
    )
    WIKI_EXPLOIT_SCENARIO = (
        "An operator registry appends an address into `operatorList` and stores "
        "`operatorIndexPlusOne[op]` during `addOperator`, but `removeOperator` "
        "only clears `operatorRole[op]`. Downstream enumeration still sees "
        "revoked operators and any payout logic keyed off the stale array keeps "
        "treating them as active."
    )
    WIKI_RECOMMENDATION = (
        "Keep add/remove style lifecycle functions same-stem and storage-slot "
        "symmetric, or delegate the bookkeeping to EnumerableSet. Preserve this "
        "row as NOT_SUBMIT_READY until evidence expands beyond the checked-in "
        "fixture pair."
    )

    SUBMISSION_POSTURE = "NOT_SUBMIT_READY"
    COVERAGE_CLAIM = "detector_fixture_smoke_only"
    PROMOTION_ALLOWED = False

    def _detect(self) -> list[Output]:
        results: list[Output] = []

        for contract in self.contracts:
            if is_vendored_or_test_contract(contract):
                continue
            if not _has_pair_surface(contract):
                continue

            public_functions: dict[str, tuple[object, set[str]]] = {}
            for function in getattr(contract, "functions_and_modifiers_declared", []) or []:
                if is_leaf_helper(function):
                    continue
                if getattr(function, "visibility", "") not in {"external", "public"}:
                    continue
                name = getattr(function, "name", "") or ""
                if not name:
                    continue
                slots = _written_slots(function, contract)
                if not slots:
                    continue
                public_functions[name] = (function, slots)

            seen_pairs: set[tuple[str, str]] = set()
            for positive_name, (positive_fn, positive_slots) in public_functions.items():
                pair = _candidate_name_pair(positive_name)
                if pair is None:
                    continue

                _, negative_name = pair
                negative_entry = public_functions.get(negative_name)
                if negative_entry is None:
                    continue

                pair_key = tuple(sorted((positive_name, negative_name)))
                if pair_key in seen_pairs:
                    continue
                seen_pairs.add(pair_key)

                negative_fn, negative_slots = negative_entry
                if positive_slots == negative_slots:
                    continue

                extra_positive = sorted(positive_slots - negative_slots)
                extra_negative = sorted(negative_slots - positive_slots)
                if not extra_positive and not extra_negative:
                    continue

                if extra_positive:
                    report_function = positive_fn
                    asymmetry = (
                        f"`{positive_name}` writes extra storage slots "
                        f"{extra_positive} that `{negative_name}` never touches"
                    )
                else:
                    report_function = negative_fn
                    asymmetry = (
                        f"`{negative_name}` writes extra storage slots "
                        f"{extra_negative} that `{positive_name}` never touches"
                    )

                info: DETECTOR_INFO = [
                    report_function,
                    " same-stem pair has asymmetric state writes: ",
                    asymmetry,
                    f". Pair `{positive_name}` ↔ `{negative_name}` uses slot sets "
                    f"{sorted(positive_slots)} vs {sorted(negative_slots)}.\n",
                ]
                results.append(self.generate_result(info))

        return results
