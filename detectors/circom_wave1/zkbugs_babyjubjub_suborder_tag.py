"""
zkbugs_babyjubjub_suborder_tag.py

Flags Panther-style Circom BabyJubJub suborder tags that instantiate
LessThan(251) against the BabyJubJub suborder but never apply the comparison
result as a constraint.

Source: zkBugs / panther-core
`veridise_babyjubjub_suborder_constraints_not_applied_correctly`.
"""
from __future__ import annotations

import re


BABYJUBJUB_SUBORDER = "2736030358979909402780800718157159386076813972158567259200215660948447373041"

_COMMENT_RE = re.compile(r"//.*?$|/\*.*?\*/", re.M | re.S)
_TEMPLATE_RE = re.compile(
    r"\btemplate\s+(?P<name>[A-Za-z_][A-Za-z0-9_]*)\s*(?:\([^)]*\))?\s*\{",
    re.M,
)
_LESS_THAN_RE = re.compile(
    r"\bcomponent\s+(?P<name>[A-Za-z_][A-Za-z0-9_]*)\s*=\s*LessThan\s*\(\s*251\s*\)\s*;",
    re.M,
)
_RANGE_CHECK_RE = re.compile(r"\b(?:Num2Bits|Bits2Num)\s*\(\s*251\s*\)")
_SUBORDER_HINT_RE = re.compile(r"(?:baby\s*jub\s*jub|babyjubjub|sub[_-]?order|suborder)", re.I)


def _strip_comments(source: str) -> str:
    return _COMMENT_RE.sub("", source)


def _line_col(source: str, offset: int) -> tuple[int, int]:
    line = source.count("\n", 0, offset) + 1
    last_newline = source.rfind("\n", 0, offset)
    col = offset + 1 if last_newline < 0 else offset - last_newline
    return line, col


def _template_end(source: str, open_brace: int) -> int:
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


def _output_constrained_to_one(body: str, component: str) -> bool:
    out = rf"{re.escape(component)}\s*\.\s*out"
    checks = [
        rf"\b{out}\s*==={{1,2}}\s*1\b",
        rf"\b1\s*==={{1,2}}\s*{out}\b",
        rf"\(\s*{out}\s*-\s*1\s*\)\s*==={{1,2}}\s*0\b",
        rf"\b0\s*==={{1,2}}\s*\(\s*{out}\s*-\s*1\s*\)",
    ]
    return any(re.search(pattern, body) for pattern in checks)


def _looks_like_babyjubjub_suborder_template(name: str, body: str) -> bool:
    return (
        BABYJUBJUB_SUBORDER in body
        and _SUBORDER_HINT_RE.search(name + "\n" + body) is not None
    )


def babyjubjub_suborder_tag_offsets(source: str) -> list[int]:
    """Return LessThan(251) offsets where BabyJubJub suborder enforcement is missing."""
    body = _strip_comments(source)
    out: list[int] = []
    for template in _TEMPLATE_RE.finditer(body):
        template_start = template.start()
        template_body_start = template.end()
        template_body_end = _template_end(body, template.end() - 1)
        template_body = body[template_body_start:template_body_end]
        template_name = template.group("name")
        if not _looks_like_babyjubjub_suborder_template(template_name, template_body):
            continue
        has_range_check = _RANGE_CHECK_RE.search(template_body) is not None
        for less_than in _LESS_THAN_RE.finditer(template_body):
            component = less_than.group("name")
            if _output_constrained_to_one(template_body, component) and has_range_check:
                continue
            out.append(template_body_start + less_than.start())
    return out


def run_text(source: str, filepath: str) -> list[dict[str, object]]:
    hits: list[dict[str, object]] = []
    for offset in babyjubjub_suborder_tag_offsets(source):
        line, col = _line_col(source, offset)
        snippet = source[offset : offset + 220].replace("\n", " ")
        hits.append(
            {
                "severity": "high",
                "line": line,
                "col": col,
                "snippet": snippet,
                "message": (
                    "BabyJubJub suborder tag compares with LessThan(251) but "
                    "does not fully enforce the comparator output and 251-bit "
                    "input range. Constrain comparator.out to 1 and range-check "
                    "the scalar before deriving BabyJubJub keys/nullifiers. "
                    "See zkBugs panther-core "
                    "veridise_babyjubjub_suborder_constraints_not_applied_correctly."
                ),
            }
        )
    return hits
