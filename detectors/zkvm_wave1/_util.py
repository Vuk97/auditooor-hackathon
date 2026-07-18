"""_util.py - shared helpers for zkvm_wave1 generic proof-system detectors."""
from __future__ import annotations

import re

_COMMENT_RE = re.compile(r"//.*?$|/\*.*?\*/", re.M | re.S)


def strip_comments(source: str) -> str:
    return _COMMENT_RE.sub("", source)


def line_col(source: str, offset: int) -> tuple[int, int]:
    line = source.count("\n", 0, offset) + 1
    last_nl = source.rfind("\n", 0, offset)
    col = offset + 1 if last_nl < 0 else offset - last_nl
    return line, col


def snippet_at(source: str, offset: int, width: int = 180) -> str:
    return source[offset:offset + width].replace("\n", " ").strip()


def fn_blocks(source: str):
    """Yield (name, start_offset, end_offset, body) for each `fn name(...) { ... }`.

    Brace-matched; tolerant of generics and where-clauses. Skips fn declarations
    without a body (trait method signatures ending in `;`).
    """
    for m in re.finditer(r"\bfn\s+([A-Za-z_][A-Za-z0-9_]*)\s*", source):
        name = m.group(1)
        brace = source.find("{", m.end())
        semi = source.find(";", m.end())
        if brace == -1:
            continue
        if semi != -1 and semi < brace:
            continue  # signature only, no body
        depth = 0
        end = brace
        for idx in range(brace, len(source)):
            ch = source[idx]
            if ch == "{":
                depth += 1
            elif ch == "}":
                depth -= 1
                if depth == 0:
                    end = idx
                    break
        yield name, m.start(), end, source[brace:end + 1]


# --- generic proof-system gates (NOT framework-specific) -------------------

_FS_SIGNAL = re.compile(
    r"\b(challenger|transcript|fiat[_-]?shamir|sponge|duplex|absorb|squeeze"
    r"|observe|sample_in_range|pow_grinding|grinding)\b", re.I)
_FIELD_SIGNAL = re.compile(
    r"\b(modulus|MODULUS|PrimeField|from_canonical|montgomery|monty|koala"
    r"|baby_?bear|goldilocks|mersenne|reduce|to_canonical|Fp\b|field)\b", re.I)
_SUMCHECK_SIGNAL = re.compile(r"\b(sumcheck|sum_check|round_poly|univariate)\b", re.I)
_MERKLE_SIGNAL = re.compile(r"\b(merkle|hash_leaf|hash_combine|compress|sibling|co_?path|auth_?path)\b", re.I)
_TWEAK_SIGNAL = re.compile(r"\b(tweak|tweakable|tree_tweak|chain_tweak|domain_sep)\b", re.I)


def is_fs_file(src: str) -> bool:
    return bool(_FS_SIGNAL.search(src))


def is_field_file(src: str) -> bool:
    return bool(_FIELD_SIGNAL.search(src))


def is_sumcheck_file(src: str) -> bool:
    return bool(_SUMCHECK_SIGNAL.search(src))


def is_merkle_file(src: str) -> bool:
    return bool(_MERKLE_SIGNAL.search(src))


def is_tweak_file(src: str) -> bool:
    return bool(_TWEAK_SIGNAL.search(src))
