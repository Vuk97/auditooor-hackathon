"""plonky2_circuit_builder_unconstrained_target.py

Flags Plonky2 `add_virtual_target()` calls whose returned target is NEVER
passed to `builder.connect(...)`, `builder.add_gate(...)`, or any arithmetic
operation (add/mul/sub/neg/arithmetic_gate) within the same function body.

Detection (regex-only):
  1. The file must look like Plonky2 (`use plonky2::*` or `CircuitBuilder<`).
  2. Within each fn body, identify every `let X = builder.add_virtual_target()`.
  3. For each virtual target X, search the rest of the function body for
     `connect(X,`, `connect(_, X)`, `add_gate(... X`, or arithmetic uses.
  4. If X is never referenced in any constraint or gate call, emit a finding.

Known FPs (documented):
  - Targets returned from the function without local constraint — a caller
    may constrain them later. The detector flags these; reviewer should
    verify the call site.
  - Targets used only in `set_target` (witness assignment) without circuit
    constraint — these ARE a bug pattern but require runtime verification;
    the detector correctly flags them as suspicious.
  - Multi-statement builder chains where the target is captured in a Vec
    rather than a named let binding (false negative, documented).

Reference: Plonky2 "add_virtual_target / connect pattern"; zkBugs
"Assigned but Unconstrained" class (Halo2 analog).
"""
from __future__ import annotations

import re
from pathlib import Path
from typing import Any

try:
    from . import _util  # type: ignore
except ImportError:  # pragma: no cover
    import importlib.util
    import sys

    _UTIL_PATH = Path(__file__).resolve().parent / "_util.py"
    _spec = importlib.util.spec_from_file_location("plonky2_wave1__util", _UTIL_PATH)
    assert _spec is not None and _spec.loader is not None
    _util = importlib.util.module_from_spec(_spec)
    sys.modules[_spec.name] = _util
    _spec.loader.exec_module(_util)


DETECTOR_ID = "plonky2_circuit_builder_unconstrained_target"

# Match: let [mut] name = builder.add_virtual_target() or add_virtual_bool_target()
_VIRTUAL_TARGET_RE = re.compile(
    r"\blet\s+(?:mut\s+)?(?P<name>[A-Za-z_][A-Za-z0-9_]*)\s*=\s*"
    r"(?:builder|cb|self\s*\.\s*builder)\s*\.\s*"
    r"add_virtual_(?:bool_|hash_)?target\s*\(",
    re.M,
)

# Constraint patterns: connect, gates, arithmetic operations taking a named target
_CONSTRAINT_TEMPLATE = (
    r"\b(?:builder|cb|self\s*\.\s*builder)\s*\.\s*"
    r"(?:connect|add_gate|arithmetic_gate|mul|add|sub|neg|square|"
    r"exp_u64|exp_power_of_2|div|inverse|is_equal|assert_bool)\s*"
    r"\([^;)]*\b{name}\b"
)


def _is_constrained(target_name: str, body_after: str) -> bool:
    """Return True if `target_name` appears in any constraint call in `body_after`."""
    pat = re.compile(
        _CONSTRAINT_TEMPLATE.format(name=re.escape(target_name)),
        re.M | re.S,
    )
    return bool(pat.search(body_after))


def find_unconstrained_targets(source: str) -> list[dict[str, Any]]:
    """Return list of dicts {target, offset, line} for virtual targets
    that are never passed to any constraint / gate call in the same fn body."""
    if not _util.is_plonky2_file(source):
        return []
    stripped = _util.strip_comments(source)

    findings: list[dict[str, Any]] = []
    for fn_name, body_start, body_end in _util.iter_fn_bodies(stripped):
        body = stripped[body_start:body_end]
        for m in _VIRTUAL_TARGET_RE.finditer(body):
            tgt = m.group("name")
            # Look for usage after the let binding
            after = body[m.end():]
            if _is_constrained(tgt, after):
                continue
            findings.append(
                {
                    "target": tgt,
                    "fn_name": fn_name,
                    "offset": body_start + m.start(),
                }
            )
    return findings


def run_text(source: str, filepath: str) -> list[dict[str, Any]]:
    hits: list[dict[str, Any]] = []
    for f in find_unconstrained_targets(source):
        line, col = _util.line_col(source, f["offset"])
        snippet = source[f["offset"]: f["offset"] + 200].replace("\n", " ")
        hits.append(
            {
                "detector_id": DETECTOR_ID,
                "file": filepath,
                "line": line,
                "col": col,
                "target": f["target"],
                "fn_name": f["fn_name"],
                "severity": "high",
                "message": (
                    f"Virtual target `{f['target']}` in fn `{f['fn_name']}` is created "
                    "via add_virtual_target but never passed to a constraint "
                    "(builder.connect / add_gate / arithmetic op). "
                    "Classic Plonky2 'Unconstrained Target' shape: the prover can "
                    "set any value in witness without the circuit enforcing correctness."
                ),
                "snippet": snippet,
            }
        )
    return hits
