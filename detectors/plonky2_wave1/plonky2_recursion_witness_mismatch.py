"""plonky2_recursion_witness_mismatch.py

Flags Plonky2 recursive proof aggregation where `add_virtual_proof_with_pis`
creates a virtual proof target but `set_proof_with_pis_target` is never called
on the same name in the witness-setting path (or vice versa: `verify_proof_in_circuit`
is called but the corresponding PI targets are never constrained with the
outer circuit's public inputs).

This captures the "recursion proof witness mismatch" pattern: the recursive
verifier expects the inner proof's public inputs to satisfy specific equations,
but the witness assignment uses a different proof or skips PI binding entirely,
allowing an invalid inner proof to satisfy the outer circuit.

Detection (regex-only):
  1. File must look like Plonky2.
  2. Identify every `let X = builder.add_virtual_proof_with_pis(...)`.
  3. Identify every `pw.set_proof_with_pis_target(X, ...)` in the same file.
  4. If any virtual proof target X lacks a corresponding set_proof_with_pis_target
     call (by name), flag it as a potential witness mismatch.
  5. Also flag when `verify_proof_in_circuit` is called without a corresponding
     `connect` of the inner_verifier_data target to the outer public inputs.

Known FPs:
  - Split across modules (target created in configure, witness set in prove).
    The detector is file-scoped; cross-file patterns are a documented FN.
  - ProofWithPublicInputsTarget stored in a struct field rather than a local
    let binding (regex misses field access; documented FN).

Reference: Plonky2 recursion pattern; "witness mismatch" class from zkBugs
corpus gnark category (similar structure in Go/Rust recursive SNARK builders).
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


DETECTOR_ID = "plonky2_recursion_witness_mismatch"

_ADD_VIRTUAL_PROOF_RE = re.compile(
    r"\blet\s+(?:mut\s+)?(?P<name>[A-Za-z_][A-Za-z0-9_]*)\s*=\s*"
    r"(?:builder|cb)\s*\.\s*add_virtual_proof_with_pis\s*\(",
    re.M,
)

_SET_PROOF_TARGET_RE = re.compile(
    r"\bpw\s*\.\s*set_proof_with_pis_target\s*\(\s*"
    r"(?:&\s*)?(?P<name>[A-Za-z_][A-Za-z0-9_]*(?:\.[A-Za-z0-9_]*)?)\s*,",
    re.M,
)

_VERIFY_PROOF_RE = re.compile(
    r"\b(?:builder|cb)\s*\.\s*verify_proof_in_circuit\s*\(",
    re.M,
)

_CONNECT_VERIFIER_DATA_RE = re.compile(
    r"\b(?:builder|cb)\s*\.\s*connect\s*\([^;)]*verifier_data",
    re.M | re.S,
)


def find_witness_mismatches(source: str) -> list[dict[str, Any]]:
    """Return findings for virtual proof targets without matching witness assignment."""
    if not _util.is_plonky2_file(source):
        return []
    stripped = _util.strip_comments(source)

    # Collect all names that appear in set_proof_with_pis_target calls
    set_names: set[str] = set()
    for m in _SET_PROOF_TARGET_RE.finditer(stripped):
        raw = m.group("name")
        # strip leading & and trailing field access
        name = raw.strip("&").split(".")[0].strip()
        set_names.add(name)

    findings: list[dict[str, Any]] = []

    # Check 1: virtual proof targets missing set_proof_with_pis_target
    for m in _ADD_VIRTUAL_PROOF_RE.finditer(stripped):
        name = m.group("name")
        if name not in set_names:
            findings.append(
                {
                    "kind": "missing_witness_assignment",
                    "target": name,
                    "offset": m.start(),
                }
            )

    # Check 2: verify_proof_in_circuit called but no connect of verifier_data
    # (catches the "inner verifier data not bound to outer PI" variant)
    if _VERIFY_PROOF_RE.search(stripped):
        if not _CONNECT_VERIFIER_DATA_RE.search(stripped):
            # Find the first verify_proof_in_circuit for offset
            vm = _VERIFY_PROOF_RE.search(stripped)
            if vm:
                findings.append(
                    {
                        "kind": "verifier_data_not_connected",
                        "target": "inner_verifier_data",
                        "offset": vm.start(),
                    }
                )

    return findings


def run_text(source: str, filepath: str) -> list[dict[str, Any]]:
    hits: list[dict[str, Any]] = []
    for f in find_witness_mismatches(source):
        line, col = _util.line_col(source, f["offset"])
        snippet = source[f["offset"]: f["offset"] + 200].replace("\n", " ")
        if f["kind"] == "missing_witness_assignment":
            msg = (
                f"Recursive proof target `{f['target']}` created via "
                "add_virtual_proof_with_pis but no corresponding "
                "pw.set_proof_with_pis_target call found in this file. "
                "Potential witness mismatch: the prover may supply an "
                "incorrect inner proof without the outer circuit detecting it."
            )
        else:
            msg = (
                "verify_proof_in_circuit called but no builder.connect of "
                "inner verifier_data to outer public inputs found. "
                "The inner verifier key is not bound to the outer circuit; "
                "a malicious prover can substitute a different proving key."
            )
        hits.append(
            {
                "detector_id": DETECTOR_ID,
                "file": filepath,
                "line": line,
                "col": col,
                "kind": f["kind"],
                "target": f["target"],
                "severity": "high",
                "message": msg,
                "snippet": snippet,
            }
        )
    return hits
