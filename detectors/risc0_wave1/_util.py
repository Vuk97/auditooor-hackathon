"""_util.py — shared helpers for risc0_wave1 regex-based detectors.

RISC Zero (https://github.com/risc0/risc0) is a zkVM where guest programs
run inside a zero-knowledge virtual machine that produces STARK proofs of
their execution. Guest code is compiled to RISC-V and run by the prover;
bugs in guest code can cause silent proof failures or incorrect journal
commits.

Key RISC Zero guest API surfaces:
  - risc0_zkvm::guest::env: env::read(), env::commit(), env::commit_slice()
  - #![no_main] with risc0_zkvm::guest::entry!(main)
  - Panic behaviour: in a zkVM guest, panic! (or .unwrap() / .expect() on
    Err) causes the prover to abort with no proof rather than a runtime
    error. The host sees a failure but no diagnostic; the prover can exploit
    this to cause selective liveness failures.
"""
from __future__ import annotations

import re

_COMMENT_RE = re.compile(r"//.*?$|/\*.*?\*/", re.M | re.S)


def strip_comments(source: str) -> str:
    return _COMMENT_RE.sub("", source)


def line_col(source: str, offset: int) -> tuple[int, int]:
    line = source.count("\n", 0, offset) + 1
    last_newline = source.rfind("\n", 0, offset)
    col = offset + 1 if last_newline < 0 else offset - last_newline
    return line, col


def is_risc0_guest_file(source: str) -> bool:
    """Heuristic: RISC Zero guest files import risc0_zkvm and use env::read/commit."""
    if re.search(r"\buse\s+risc0_zkvm\s*::", source):
        return True
    if re.search(r"\benv\s*::\s*(?:read|commit|commit_slice|write)\b", source):
        return True
    if re.search(r"\brisc0_zkvm\s*::\s*guest\b", source):
        return True
    return False
