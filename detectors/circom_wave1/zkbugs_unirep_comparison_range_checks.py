"""
Detect Unirep-style Circom comparison gadgets used without input range checks.

Circomlib comparison gadgets such as LessThan(n) assume each input already fits
in n bits. If a raw signal input is wired directly into the comparator, a
malicious prover can use a large field element like p - 1 to overflow the
internal n-bit decomposition and make an out-of-range value compare as small.

Source: zkBugs
`Unirep/Unirep/veridise_missing_range_checks_on_comparison_circuits`.
"""
from __future__ import annotations

import re


_COMMENT_RE = re.compile(r"//.*?$|/\*.*?\*/", re.M | re.S)
_TEMPLATE_RE = re.compile(r"\btemplate\s+(?P<name>[A-Za-z_]\w*)\s*\([^)]*\)\s*{")
_SIGNAL_INPUT_RE = re.compile(r"\bsignal\s+input\s+(?P<name>[A-Za-z_]\w*)\b")
_NUM2BITS_RE = re.compile(
    r"\bcomponent\s+(?P<component>[A-Za-z_]\w*)\s*=\s*Num2Bits\s*"
    r"\(\s*(?P<bits>\d+)\s*\)\s*;"
)
_COMPARATOR_RE = re.compile(
    r"\bcomponent\s+(?P<component>[A-Za-z_]\w*)\s*=\s*"
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
        open_brace = source.find("{", match.end() - 1)
        if open_brace < 0:
            continue
        out.append(
            (
                match.group("name"),
                match.start(),
                source[match.start() : _matching_brace(source, open_brace)],
            )
        )
    return out


def _normalized(token: str) -> str:
    return re.sub(r"\s+", "", token)


def _range_checked_inputs(template_source: str) -> dict[str, int]:
    components = {
        match.group("component"): int(match.group("bits"))
        for match in _NUM2BITS_RE.finditer(template_source)
    }
    checked: dict[str, int] = {}
    for match in _ASSIGN_RE.finditer(template_source):
        lhs = _normalized(match.group("lhs"))
        rhs = _normalized(match.group("rhs"))
        for target, candidate in ((lhs, rhs), (rhs, lhs)):
            if not target.endswith(".in"):
                continue
            component = target[:-3]
            if component not in components or not re.fullmatch(r"[A-Za-z_]\w*", candidate):
                continue
            bits = components[component]
            checked[candidate] = min(bits, checked.get(candidate, bits))
    return checked


def _comparator_inputs(template_source: str, component: str) -> set[str]:
    component_input = re.compile(rf"\b{re.escape(component)}\s*\.\s*in\s*\[\s*[01]\s*\]")
    inputs: set[str] = set()
    for match in _ASSIGN_RE.finditer(template_source):
        lhs = _normalized(match.group("lhs"))
        rhs = _normalized(match.group("rhs"))
        if component_input.fullmatch(lhs) and re.fullmatch(r"[A-Za-z_]\w*", rhs):
            inputs.add(rhs)
        if component_input.fullmatch(rhs) and re.fullmatch(r"[A-Za-z_]\w*", lhs):
            inputs.add(lhs)
    return inputs


def comparison_range_check_hits(source: str) -> list[dict[str, object]]:
    body = _strip_comments_preserve_offsets(source)
    hits: list[dict[str, object]] = []
    for template_name, template_offset, template_source in _templates(body):
        signal_inputs = {match.group("name") for match in _SIGNAL_INPUT_RE.finditer(template_source)}
        if not signal_inputs:
            continue

        checked = _range_checked_inputs(template_source)
        for match in _COMPARATOR_RE.finditer(template_source):
            bits = int(match.group("bits"))
            component = match.group("component")
            missing = [
                name
                for name in sorted(_comparator_inputs(template_source, component) & signal_inputs)
                if checked.get(name, bits + 1) > bits
            ]
            if not missing:
                continue

            offset = template_offset + match.start()
            line, col = _line_col(source, offset)
            hits.append(
                {
                    "severity": "high",
                    "line": line,
                    "col": col,
                    "template": template_name,
                    "component": component,
                    "comparator": match.group("kind"),
                    "bits": bits,
                    "inputs": missing,
                    "snippet": source[offset : offset + 180].replace("\n", " "),
                    "message": (
                        f"{template_name}.{component} wires raw signal input(s) "
                        f"{', '.join(missing)} into {match.group('kind')}({bits}) "
                        "without a matching Num2Bits range check. Circomlib "
                        "comparison inputs must be pre-bounded or large field "
                        "elements can satisfy the comparison via overflow "
                        "(zkBugs Unirep V-UNI-VUL-002)."
                    ),
                }
            )
    return hits


def run_text(source: str, filepath: str) -> list[dict[str, object]]:
    return comparison_range_check_hits(source)
