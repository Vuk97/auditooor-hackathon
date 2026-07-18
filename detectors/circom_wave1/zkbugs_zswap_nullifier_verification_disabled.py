"""
Detect Panther ZSwapV1-style nullifier verification that can be disabled.

Source: zkBugs / panther-core
`veridise_nullifier_verification_can_be_disabled`

The vulnerable ZSwapV1 circuit checks `zAccountUtxoInNullifier` with
`ForceEqualIfEnabled()`, but wires `.enabled` to `zAccountUtxoInSpendPrivKey`.
Since zero is a valid BabyJubJub private key, a prover can set the key to zero
and disable the nullifier equality check.
"""
from __future__ import annotations

import re


_COMMENT_RE = re.compile(r"//.*?$|/\*.*?\*/", re.M | re.S)
_TEMPLATE_RE = re.compile(r"\btemplate\s+(?P<name>[A-Za-z_]\w*)\s*(?:\([^)]*\))?\s*{")
_FORCE_EQUAL_RE = re.compile(
    r"\bcomponent\s+(?P<comp>[A-Za-z_]\w*)\s*=\s*ForceEqualIfEnabled\s*\(\s*\)\s*;"
)
_ASSIGN_RE = re.compile(
    r"\b(?P<lhs>[A-Za-z_]\w*(?:\s*\.\s*\w+)?(?:\s*\[\s*\d+\s*\])?)\s*"
    r"(?P<op><==|<--|===|==>)\s*"
    r"(?P<rhs>[A-Za-z_]\w*(?:\s*\.\s*\w+)?(?:\s*\[\s*\d+\s*\])?|[0-9]+)\b"
)
_NULLIFIER_RE = re.compile(r"nullifier", re.I)
_HASHER_RE = re.compile(r"(?:hasher|hash|poseidon|out)$", re.I)
_KEY_GATED_RE = re.compile(r"(?:spend|priv|private|key)", re.I)
_ZSWAP_CONTEXT_RE = re.compile(r"(?:ZSwap|zAccount|Utxo|ForceEqualIfEnabled)", re.I)


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
        end = _matching_brace(source, open_brace)
        out.append((match.group("name"), match.start(), source[match.start() : end]))
    return out


def _compact_signal(value: str) -> str:
    return re.sub(r"\s+", "", value)


def _component_assignments(template_source: str, component: str) -> dict[str, str]:
    assignments: dict[str, str] = {}
    for match in _ASSIGN_RE.finditer(template_source):
        lhs = _compact_signal(match.group("lhs"))
        rhs = _compact_signal(match.group("rhs"))
        if lhs.startswith(component + "."):
            assignments[lhs[len(component) + 1 :]] = rhs
    return assignments


def _is_forced_on(enabled_rhs: str, template_source: str) -> bool:
    if enabled_rhs == "1":
        return True
    return re.search(rf"\b{re.escape(enabled_rhs)}\s*==={{1,2}}\s*1\b", template_source) is not None


def zswap_nullifier_verification_disabled_hits(source: str) -> list[dict[str, object]]:
    body = _strip_comments_preserve_offsets(source)
    hits: list[dict[str, object]] = []
    for template_name, template_offset, template_source in _templates(body):
        if _ZSWAP_CONTEXT_RE.search(template_name + "\n" + template_source) is None:
            continue
        for match in _FORCE_EQUAL_RE.finditer(template_source):
            component = match.group("comp")
            assignments = _component_assignments(template_source, component)
            enabled_rhs = assignments.get("enabled")
            in0 = assignments.get("in[0]", "")
            in1 = assignments.get("in[1]", "")
            if not enabled_rhs or _is_forced_on(enabled_rhs, template_source):
                continue
            nullifier_inputs = [value for value in (in0, in1) if _NULLIFIER_RE.search(value)]
            hash_inputs = [value for value in (in0, in1) if _HASHER_RE.search(value)]
            if not nullifier_inputs or not hash_inputs:
                continue
            if _KEY_GATED_RE.search(enabled_rhs) is None:
                continue
            offset = template_offset + match.start()
            line, col = _line_col(source, offset)
            hits.append(
                {
                    "severity": "critical",
                    "line": line,
                    "col": col,
                    "template": template_name,
                    "component": component,
                    "enabled": enabled_rhs,
                    "snippet": source[offset : offset + 240].replace("\n", " "),
                    "message": (
                        f"{template_name}.{component} verifies a nullifier with "
                        f"ForceEqualIfEnabled() but gates `.enabled` on `{enabled_rhs}`. "
                        "If the key can be zero, the equality check is disabled and the "
                        "nullifier can be chosen arbitrarily. Force `.enabled <== 1` for "
                        "nullifier verification. See zkBugs panther-core "
                        "veridise_nullifier_verification_can_be_disabled."
                    ),
                }
            )
    return hits


def run_text(source: str, filepath: str) -> list[dict[str, object]]:
    return zswap_nullifier_verification_disabled_hits(source)
