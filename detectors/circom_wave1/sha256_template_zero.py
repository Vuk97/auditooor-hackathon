"""
Detect zkBugs SHA256 template zero-hash selector evidence.

The zkemail SHA256 bug combines two shapes:
  * Sha256* templates derive `inBlockIndex` from a hinted `paddedInLength`
    and pass `inBlockIndex - 1` into `ItemAtIndex`.
  * `ItemAtIndex` only uses a LessThan bounds check and never constrains the
    equality selector sum to exactly one selected array entry.

That lets out-of-bounds indices leave the selected output at zero. This
detector is intentionally narrow and requires both the SHA256 caller shape and
the vulnerable `ItemAtIndex` helper in the same Circom source.
"""
from __future__ import annotations

import re


SHA256_TEMPLATES = {
    "Sha256General",
    "Sha256Partial",
    "Sha256Bytes",
    "Sha256BytesPartial",
}

_COMMENT_RE = re.compile(r"//.*?$|/\*.*?\*/", re.M | re.S)
_TEMPLATE_RE = re.compile(r"\btemplate\s+(?P<name>[A-Za-z_]\w*)\s*(?:\([^)]*\))?\s*\{")
_ITEM_AT_INDEX_COMPONENT_RE = re.compile(
    r"\bcomponent\s+(?P<name>[A-Za-z_]\w*)\s*=\s*ItemAtIndex\s*\("
)
_LESSTHAN_RE = re.compile(r"\bcomponent\s+[A-Za-z_]\w*\s*=\s*LessThan\s*\(")
_INDEX_INPUT_RE = re.compile(r"\bsignal\s+input\s+index\b")
_EQS_HINT_RE = re.compile(r"\beqs\s*(?:\[|\.)")
_SELECTOR_SUM_NAME = r"(?:eqs|[A-Za-z0-9_]*sum|total|acc|selector[A-Za-z0-9_]*)"


def _blank_comments(source: str) -> str:
    def blank(match: re.Match[str]) -> str:
        return "".join("\n" if ch == "\n" else " " for ch in match.group(0))

    return _COMMENT_RE.sub(blank, source)


def _line_col(source: str, offset: int) -> tuple[int, int]:
    line = source.count("\n", 0, offset) + 1
    last_newline = source.rfind("\n", 0, offset)
    col = offset + 1 if last_newline < 0 else offset - last_newline
    return line, col


def _matching_brace(source: str, open_brace: int) -> int:
    depth = 0
    for idx in range(open_brace, len(source)):
        if source[idx] == "{":
            depth += 1
        elif source[idx] == "}":
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
        end = _matching_brace(source, open_brace)
        out.append((match.group("name"), match.start(), source[match.start():end]))
    return out


def _norm(source: str) -> str:
    return re.sub(r"\s+", "", source)


def _sha256_uses_item_at_index_zero_shape(template_source: str) -> bool:
    compact = _norm(template_source)
    if "paddedInLength" not in template_source or "inBlockIndex" not in template_source:
        return False
    if not re.search(r"inBlockIndex\s*<--\s*\(?\s*paddedInLength\s*>>\s*9\s*\)?", template_source):
        return False
    if "paddedInLength===inBlockIndex*512" not in compact:
        return False

    for component in _ITEM_AT_INDEX_COMPONENT_RE.finditer(template_source):
        name = component.group("name")
        index_wire = re.compile(
            rf"\b{re.escape(name)}\s*\.\s*index\s*<==\s*"
            r"\(?\s*inBlockIndex\s*-\s*1\s*\)?"
        )
        if index_wire.search(template_source):
            return True
    return False


def _has_exactly_one_selector_constraint(template_source: str) -> bool:
    """Return true for the fixed shape: all eq selectors must sum to one."""
    compact = _norm(template_source)
    if re.search(rf"{_SELECTOR_SUM_NAME}===1", compact, re.I):
        return True
    if re.search(rf"1==={_SELECTOR_SUM_NAME}", compact, re.I):
        return True
    if re.search(
        rf"assert\s*\(\s*{_SELECTOR_SUM_NAME}\s*==\s*1\s*\)",
        template_source,
        re.I,
    ):
        return True
    return False


def _vulnerable_item_at_index_templates(source: str) -> list[dict[str, object]]:
    hits: list[dict[str, object]] = []
    for template_name, offset, template_source in _templates(source):
        if template_name != "ItemAtIndex":
            continue
        if not _INDEX_INPUT_RE.search(template_source):
            continue
        if not _LESSTHAN_RE.search(template_source):
            continue
        if not _EQS_HINT_RE.search(template_source):
            continue
        if _has_exactly_one_selector_constraint(template_source):
            continue
        line, col = _line_col(source, offset)
        hits.append(
            {
                "template": template_name,
                "line": line,
                "col": col,
                "snippet": template_source[:240].replace("\n", " "),
            }
        )
    return hits


def sha256_template_zero_hits(source: str) -> list[dict[str, object]]:
    clean = _blank_comments(source)
    vulnerable_items = _vulnerable_item_at_index_templates(clean)
    if not vulnerable_items:
        return []

    sha_templates: list[str] = []
    for template_name, _offset, template_source in _templates(clean):
        if template_name not in SHA256_TEMPLATES:
            continue
        if _sha256_uses_item_at_index_zero_shape(template_source):
            sha_templates.append(template_name)

    if not sha_templates:
        return []

    hits: list[dict[str, object]] = []
    for item in vulnerable_items:
        hits.append(
            {
                "severity": "high",
                "line": item["line"],
                "col": item["col"],
                "template": item["template"],
                "sha256_templates": sorted(sha_templates),
                "snippet": item["snippet"],
                "message": (
                    "SHA256 template(s) derive `inBlockIndex` from hinted "
                    "`paddedInLength` and feed `inBlockIndex - 1` into an "
                    "`ItemAtIndex` helper that only uses LessThan bounds "
                    "evidence and does not constrain the equality-selector "
                    "sum to 1. Out-of-bounds indices can leave the selected "
                    "hash chunk as all-zero."
                ),
            }
        )
    return hits


def run_text(source: str, filepath: str) -> list[dict[str, object]]:
    return sha256_template_zero_hits(source)
