"""
Detect Dark Forest v0.3 RangeProof missing bit-length checks.

The historical ZKBugs case wires arithmetic expressions such as
`max_abs_value + in` into circomlib `LessThan(bits)` gadgets. `LessThan`
assumes its inputs are already bounded to the comparator width, so the
RangeProof template needs explicit Num2Bits checks for those comparator input
expressions (or intermediates carrying them).

Source: zkBugs
`darkforest-eth/darkforest-v0.3/daira_hopwood_darkforest_v0_3_missing_bit_length_check`.
"""
from __future__ import annotations

import re


_COMMENT_RE = re.compile(r"//.*?$|/\*.*?\*/", re.M | re.S)
_TEMPLATE_RE = re.compile(r"\btemplate\s+(?P<name>[A-Za-z_]\w*)\s*\((?P<params>[^)]*)\)\s*{")
_SIGNAL_RE = re.compile(r"\bsignal\s+(?:input\s+|output\s+)?(?P<name>[A-Za-z_]\w*)\b")
_NUM2BITS_RE = re.compile(
    r"\bcomponent\s+(?P<comp>[A-Za-z_]\w*)\s*=\s*Num2Bits\s*\(\s*(?P<bits>[^)]+?)\s*\)\s*;"
)
_LESS_THAN_RE = re.compile(
    r"\bcomponent\s+(?P<comp>[A-Za-z_]\w*)\s*=\s*LessThan\s*\(\s*(?P<bits>[^)]+?)\s*\)\s*;"
)
_ASSIGN_RE = re.compile(
    r"(?P<lhs>[A-Za-z_]\w*(?:\s*\.\s*\w+)?(?:\s*\[\s*[^]]+\s*\])?)\s*"
    r"(?P<op><==|<--|===|==>|-->)\s*"
    r"(?P<rhs>[^;]+?)\s*;"
)


def _strip_comments_preserve_offsets(source: str) -> str:
    return _COMMENT_RE.sub(lambda match: " " * (match.end() - match.start()), source)


def _line_col(source: str, offset: int) -> tuple[int, int]:
    line = source.count("\n", 0, offset) + 1
    last_newline = source.rfind("\n", 0, offset)
    col = offset + 1 if last_newline < 0 else offset - last_newline
    return line, col


def _matching_brace(source: str, open_brace: int) -> int:
    depth = 0
    for idx in range(open_brace, len(source)):
        char = source[idx]
        if char == "{":
            depth += 1
        elif char == "}":
            depth -= 1
            if depth == 0:
                return idx + 1
    return len(source)


def _templates(source: str) -> list[tuple[str, list[str], int, str]]:
    out: list[tuple[str, list[str], int, str]] = []
    for match in _TEMPLATE_RE.finditer(source):
        open_brace = source.find("{", match.end() - 1)
        if open_brace < 0:
            continue
        end = _matching_brace(source, open_brace)
        params = [
            part.strip().split()[-1]
            for part in match.group("params").split(",")
            if part.strip()
        ]
        out.append((match.group("name"), params, match.start(), source[match.start():end]))
    return out


def _norm_expr(value: str) -> str:
    return re.sub(r"\s+", "", value)


def _bits_sufficient(check_bits: str, comparator_bits: str) -> bool:
    check = _norm_expr(check_bits)
    comparator = _norm_expr(comparator_bits)
    if check == comparator:
        return True
    if check.isdigit() and comparator.isdigit():
        return int(check) <= int(comparator)
    return False


def _assignment_pairs(template_source: str) -> list[tuple[str, str]]:
    pairs: list[tuple[str, str]] = []
    for match in _ASSIGN_RE.finditer(template_source):
        pairs.append((_norm_expr(match.group("lhs")), _norm_expr(match.group("rhs"))))
    return pairs


def _range_checked_expressions(template_source: str, comparator_bits: str) -> set[str]:
    num2bits = {
        match.group("comp"): match.group("bits")
        for match in _NUM2BITS_RE.finditer(template_source)
        if _bits_sufficient(match.group("bits"), comparator_bits)
    }
    checked: set[str] = set()
    aliases: dict[str, str] = {}
    for lhs, rhs in _assignment_pairs(template_source):
        if re.fullmatch(r"[A-Za-z_]\w*", lhs):
            aliases[lhs] = rhs
        for comp in num2bits:
            if lhs == f"{comp}.in":
                checked.add(rhs)
                if rhs in aliases:
                    checked.add(aliases[rhs])
            if rhs == f"{comp}.in":
                checked.add(lhs)
                if lhs in aliases:
                    checked.add(aliases[lhs])
    return checked


def _less_than_inputs(template_source: str, component: str) -> list[str]:
    inputs: list[str] = []
    prefix = re.compile(rf"{re.escape(component)}\.in\[[^]]+\]")
    for lhs, rhs in _assignment_pairs(template_source):
        if prefix.fullmatch(lhs):
            inputs.append(rhs)
    return inputs


def _interesting_unchecked_inputs(
    expressions: list[str],
    checked: set[str],
    names: set[str],
) -> list[str]:
    unchecked: list[str] = []
    for expression in expressions:
        if expression in checked:
            continue
        if expression.isdigit():
            continue
        if not any(re.search(rf"\b{re.escape(name)}\b", expression) for name in names):
            continue
        unchecked.append(expression)
    return unchecked


def darkforest_bit_length_check_hits(source: str) -> list[dict[str, object]]:
    body = _strip_comments_preserve_offsets(source)
    hits: list[dict[str, object]] = []
    for template_name, params, template_offset, template_source in _templates(body):
        if template_name != "RangeProof":
            continue
        signal_names = {match.group("name") for match in _SIGNAL_RE.finditer(template_source)}
        names = signal_names | set(params)
        if not names:
            continue
        for match in _LESS_THAN_RE.finditer(template_source):
            comp = match.group("comp")
            bits = match.group("bits")
            unchecked = _interesting_unchecked_inputs(
                _less_than_inputs(template_source, comp),
                _range_checked_expressions(template_source, bits),
                names,
            )
            if not unchecked:
                continue
            offset = template_offset + match.start()
            line, col = _line_col(source, offset)
            hits.append(
                {
                    "severity": "high",
                    "line": line,
                    "col": col,
                    "template": template_name,
                    "component": comp,
                    "bits": _norm_expr(bits),
                    "unchecked_inputs": unchecked,
                    "snippet": source[offset : offset + 180].replace("\n", " "),
                    "message": (
                        f"RangeProof.{comp} feeds LessThan({bits.strip()}) with "
                        f"unchecked expression(s): {', '.join(unchecked)}. "
                        "Add Num2Bits checks with matching or narrower bit length "
                        "before reusing these values as comparator inputs."
                    ),
                }
            )
    return hits


def run_text(source: str, filepath: str) -> list[dict[str, object]]:
    return darkforest_bit_length_check_hits(source)
