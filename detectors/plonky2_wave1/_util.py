"""_util.py — shared helpers for plonky2_wave1 regex-based detectors.

Plonky2 (Polygon's recursive ZK framework, https://github.com/0xPolygonZero/plonky2)
is written in Rust. These helpers extract Plonky2-specific shape info from Rust
source WITHOUT requiring tree-sitter-rust. They operate on raw strings.

Designed as a sister module to detectors/halo2_wave1/_util.py. The
Plonky2 wave intentionally uses the regex path to keep new framework
detectors decoupled from the heavier AST stack.

Plonky2 key API surfaces detected:
  - CircuitBuilder<F,D>: add_virtual_target, connect, arithmetic_gate, etc.
  - Poseidon sponge: poseidon_hash_one_field, poseidon_two_to_one
  - Recursion: add_virtual_proof_with_pis, verify_proof_in_circuit
  - Witness: PartialWitness, set_target, set_proof_with_pis_target
"""
from __future__ import annotations

import re
from typing import Iterable

_COMMENT_RE = re.compile(r"//.*?$|/\*.*?\*/", re.M | re.S)


def strip_comments(source: str) -> str:
    """Strip // and /* */ comments. Conservative; does not handle string
    literals containing comment-like substrings."""
    return _COMMENT_RE.sub("", source)


def line_col(source: str, offset: int) -> tuple[int, int]:
    """1-indexed line, 1-indexed column for a byte offset into `source`."""
    line = source.count("\n", 0, offset) + 1
    last_newline = source.rfind("\n", 0, offset)
    col = offset + 1 if last_newline < 0 else offset - last_newline
    return line, col


def block_end(source: str, open_brace_offset: int) -> int:
    """Return the offset just past the matching `}` for the `{` at
    `open_brace_offset`. Returns len(source) if unbalanced (degraded)."""
    depth = 0
    for idx in range(open_brace_offset, len(source)):
        ch = source[idx]
        if ch == "{":
            depth += 1
        elif ch == "}":
            depth -= 1
            if depth == 0:
                return idx + 1
    return len(source)


def is_plonky2_file(source: str) -> bool:
    """Heuristic: Plonky2 sources import plonky2:: crate types or
    use CircuitBuilder<F,D> directly."""
    if re.search(r"\buse\s+plonky2\s*::", source):
        return True
    if re.search(r"\bCircuitBuilder\s*<", source):
        return True
    if re.search(r"\bPartialWitness\s*<", source):
        return True
    if re.search(r"\bplonky2_field\s*::", source):
        return True
    return False


_FN_BODY_RE = re.compile(
    # Match `fn name` then skip generic params (including nested) by matching
    # up to the opening `(` of the parameter list, then up to `{`.
    # The [^{;]* after the closing paren handles `-> ReturnType`.
    r"\bfn\s+(?P<name>[A-Za-z_][A-Za-z0-9_]*)[^(]*\([^)]*\)[^{;]*\{",
    re.M | re.S,
)


def iter_fn_bodies(source: str) -> Iterable[tuple[str, int, int]]:
    """Yield (fn_name, body_start, body_end) for each `fn name(...) { ... }`.
    Body bounds exclude the outer `{}`."""
    for m in _FN_BODY_RE.finditer(source):
        fn_name = m.group("name") if m.lastgroup else "unknown"
        open_brace = m.end() - 1
        end = block_end(source, open_brace)
        yield fn_name.strip(), open_brace + 1, end - 1


def find_virtual_targets(body: str) -> list[str]:
    """Extract names of virtual targets added via `builder.add_virtual_target()`
    or `builder.add_virtual_bool_target()`. Best-effort; regex hint."""
    out: list[str] = []
    for m in re.finditer(
        r"\blet\s+(?:mut\s+)?(?P<name>[A-Za-z_][A-Za-z0-9_]*)\s*=\s*"
        r"(?:builder|cb)\s*\.\s*add_virtual_(?:bool_)?target\s*\(",
        body,
    ):
        out.append(m.group("name"))
    return out


def find_connect_calls(body: str) -> list[str]:
    """Extract the first argument of each builder.connect(a, b) call.
    Returns bare identifier names."""
    out: list[str] = []
    for m in re.finditer(
        r"\b(?:builder|cb)\s*\.\s*connect\s*\(\s*"
        r"(?P<lhs>[A-Za-z_][A-Za-z0-9_.]*)\s*,",
        body,
    ):
        ident = m.group("lhs").rsplit(".", 1)[-1]
        out.append(ident)
    return out


def find_arithmetic_gate_uses(body: str) -> list[str]:
    """Find names of targets used in add_gate / arithmetic_gate calls."""
    out: list[str] = []
    for m in re.finditer(
        r"\b(?:builder|cb)\s*\.\s*(?:add_gate|arithmetic_gate|mul|add|sub)"
        r"\s*\(\s*(?P<arg>[A-Za-z_][A-Za-z0-9_.]*)",
        body,
    ):
        ident = m.group("arg").rsplit(".", 1)[-1]
        out.append(ident)
    return out
