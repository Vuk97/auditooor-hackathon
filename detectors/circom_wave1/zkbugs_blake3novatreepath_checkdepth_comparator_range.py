"""
Detect Blake3NovaTreePath_CheckDepth-style Circom comparator precondition bugs.

Circomlib LessThan/GreaterEqThan gadgets assume both inputs are already bounded
to the comparator bit width. This detector flags templates that wire free
`signal input` values directly into those comparators without a same-template
Num2Bits range check of matching or narrower width.

Source: zkBugs
`banyancomputer/hot-proofs-blake3-circom/koukyosyumei_checkdepth_comparator_overflow`.
"""
from __future__ import annotations

import re


_COMMENT_RE = re.compile(r"//.*?$|/\*.*?\*/", re.M | re.S)
_TEMPLATE_RE = re.compile(r"\btemplate\s+(?P<name>[A-Za-z_]\w*)\s*\([^)]*\)\s*{")
_SIGNAL_INPUT_RE = re.compile(r"\bsignal\s+input\s+(?P<name>[A-Za-z_]\w*)\b")
_NUM2BITS_RE = re.compile(
    r"\bcomponent\s+(?P<comp>[A-Za-z_]\w*)\s*=\s*Num2Bits\s*\(\s*(?P<bits>\d+)\s*\)\s*;"
)
_COMPARATOR_RE = re.compile(
    r"\bcomponent\s+(?P<comp>[A-Za-z_]\w*)\s*=\s*"
    r"(?P<kind>LessThan|LessEqThan|GreaterThan|GreaterEqThan)\s*"
    r"\(\s*(?P<bits>\d+)\s*\)\s*;"
)
_ASSIGN_RE = re.compile(
    r"\b(?P<lhs>[A-Za-z_]\w*(?:\s*\.\s*\w+)?(?:\s*\[\s*\d+\s*\])?)\s*"
    r"(?P<op><==|<--|===|==>)\s*"
    r"(?P<rhs>[A-Za-z_]\w*(?:\s*\.\s*\w+)?(?:\s*\[\s*\d+\s*\])?)"
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


def _templates(source: str) -> list[tuple[str, int, str]]:
    out: list[tuple[str, int, str]] = []
    for match in _TEMPLATE_RE.finditer(source):
        start = match.start()
        open_brace = source.find("{", match.end() - 1)
        if open_brace < 0:
            continue
        end = _matching_brace(source, open_brace)
        out.append((match.group("name"), start, source[start:end]))
    return out


def _range_checked_inputs(template_source: str) -> dict[str, int]:
    """Return signal names constrained by Num2Bits and their narrowest width."""
    components: dict[str, int] = {
        match.group("comp"): int(match.group("bits")) for match in _NUM2BITS_RE.finditer(template_source)
    }
    checked: dict[str, int] = {}
    for match in _ASSIGN_RE.finditer(template_source):
        lhs = re.sub(r"\s+", "", match.group("lhs"))
        rhs = re.sub(r"\s+", "", match.group("rhs"))
        pairs = ((lhs, rhs), (rhs, lhs))
        for target, candidate in pairs:
            if not target.endswith(".in"):
                continue
            comp = target[:-3]
            if comp not in components:
                continue
            if not re.fullmatch(r"[A-Za-z_]\w*", candidate):
                continue
            bits = components[comp]
            checked[candidate] = min(bits, checked.get(candidate, bits))
    return checked


def _comparator_inputs(template_source: str, component: str) -> set[str]:
    inputs: set[str] = set()
    component_in = re.compile(rf"\b{re.escape(component)}\s*\.\s*in\s*\[\s*[01]\s*\]")
    for match in _ASSIGN_RE.finditer(template_source):
        lhs = re.sub(r"\s+", "", match.group("lhs"))
        rhs = re.sub(r"\s+", "", match.group("rhs"))
        if component_in.fullmatch(lhs) and re.fullmatch(r"[A-Za-z_]\w*", rhs):
            inputs.add(rhs)
        if component_in.fullmatch(rhs) and re.fullmatch(r"[A-Za-z_]\w*", lhs):
            inputs.add(lhs)
    return inputs


def comparator_missing_range_check_hits(source: str) -> list[dict[str, object]]:
    body = _strip_comments_preserve_offsets(source)
    hits: list[dict[str, object]] = []
    for template_name, template_offset, template_source in _templates(body):
        signal_inputs = {match.group("name") for match in _SIGNAL_INPUT_RE.finditer(template_source)}
        if not signal_inputs:
            continue
        checked = _range_checked_inputs(template_source)
        for match in _COMPARATOR_RE.finditer(template_source):
            comp = match.group("comp")
            bits = int(match.group("bits"))
            raw_inputs = []
            for name in sorted(_comparator_inputs(template_source, comp) & signal_inputs):
                if checked.get(name, bits + 1) > bits:
                    raw_inputs.append(name)
            if not raw_inputs:
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
                    "comparator": match.group("kind"),
                    "bits": bits,
                    "inputs": raw_inputs,
                    "snippet": source[offset : offset + 180].replace("\n", " "),
                    "message": (
                        f"{template_name}.{comp} uses {match.group('kind')}({bits}) "
                        f"with unbounded signal input(s): {', '.join(raw_inputs)}. "
                        "Range-check each comparator input with Num2Bits of matching "
                        "or narrower width before the comparison."
                    ),
                }
            )
    return hits


def run_text(source: str, filepath: str) -> list[dict[str, object]]:
    return comparator_missing_range_check_hits(source)
