"""
Detect Zkopru-style ERC20Sum checks keyed only by input token addresses.

The historical zkBugs candidate
`circom__under-constrained__circuit-does-not-check-the-erc-20-sum-correctly`
used an ERC20 balance check where each outflow sum was selected by
`spending_note_token_addr[i]`. That proves conservation only for token
addresses already present in the input notes; output notes with novel token
addresses can be omitted unless the circuit separately constrains every output
token address to appear in the input set.

This is intentionally narrow and advisory. It reports templates that contain
the input-keyed ERC20Sum equality shape and do not contain a recognizable
output-address membership guard.
"""
from __future__ import annotations

import argparse
import json
import re
from pathlib import Path
from typing import Iterable


_COMMENT_RE = re.compile(r"//.*?$|/\*.*?\*/", re.M | re.S)
_TEMPLATE_RE = re.compile(r"\btemplate\s+(?P<name>[A-Za-z_]\w*)\s*(?:\([^)]*\))?\s*{")
_COMPONENT_ARRAY_RE = re.compile(
    r"\bcomponent\s+(?P<name>[A-Za-z_]\w*)\s*\[[^\]]+\]\s*=\s*ERC20Sum\s*\(",
    re.M,
)
_INPUT_KEYED_ADDR_RE = re.compile(
    r"\b(?P<outflow>[A-Za-z_]\w*)\s*\[\s*(?P<idx>[A-Za-z_]\w*)\s*\]\s*\.\s*addr\s*<==\s*"
    r"(?P<input_addr>[A-Za-z_]\w*)\s*\[\s*(?P=idx)\s*\]\s*;",
    re.M,
)
_OUTFLOW_EQUALITY_TEMPLATE = (
    r"\b[A-Za-z_]\w*\s*\[\s*{idx}\s*\]\s*\.\s*out\s*===\s*{outflow}\s*"
    r"\[\s*{idx}\s*\]\s*\.\s*out\b"
    r"|\b{outflow}\s*\[\s*{idx}\s*\]\s*\.\s*out\s*===\s*"
    r"[A-Za-z_]\w*\s*\[\s*{idx}\s*\]\s*\.\s*out\b"
)
_OUTPUT_ADDR_RE = re.compile(r"\b(?P<name>[A-Za-z_]\w*(?:output|withdrawal|new)[A-Za-z_0-9]*token[A-Za-z_0-9]*addr[A-Za-z_0-9]*)\b", re.I)
_DECLARED_OUTPUT_ADDR_RE = re.compile(
    r"\bsignal\s+(?:input\s+)?(?P<name>[A-Za-z_]\w*(?:output|withdrawal|new)[A-Za-z_0-9]*token[A-Za-z_0-9]*addr[A-Za-z_0-9]*)\s*\[",
    re.I,
)
_IS_EQUAL_COMPONENT_RE = re.compile(
    r"\bcomponent\s+(?P<comp>[A-Za-z_]\w*(?:\s*\[[^\]]+\])*)\s*=\s*IsEqual\s*\(\s*\)\s*;",
    re.M,
)
_ASSIGN_RE = re.compile(
    r"\b(?P<lhs>[A-Za-z_]\w*(?:\s*\[[^\]]+\])*(?:\s*\.\s*\w+(?:\s*\[[^\]]+\])?)?)\s*"
    r"(?P<op><==|===|==>)\s*"
    r"(?P<rhs>[A-Za-z_]\w*(?:\s*\[[^\]]+\])*(?:\s*\.\s*\w+(?:\s*\[[^\]]+\])?)?)",
    re.M,
)


def _blank_comments(source: str) -> str:
    def blank(match: re.Match[str]) -> str:
        return "".join("\n" if char == "\n" else " " for char in match.group(0))

    return _COMMENT_RE.sub(blank, source)


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
        out.append((match.group("name"), match.start(), source[match.start():end]))
    return out


def _compact(expr: str) -> str:
    return re.sub(r"\s+", "", expr)


def _has_named_membership_guard(body: str) -> bool:
    guard_hints = (
        "AllOutputsInInputs",
        "OutputTokenAddressInInputs",
        "all_outputs_in_inputs",
        "output_token_addr_in_inputs",
        "outputTokenAddrInInputs",
    )
    return any(hint in body for hint in guard_hints)


def _has_isequal_membership_guard(body: str, input_addr: str, output_addr_names: set[str]) -> bool:
    """Recognize the common guard shape: IsEqual(output_addr[j], input_addr[i]) summed to 1."""
    if not output_addr_names:
        return False

    equal_components = [_compact(match.group("comp")) for match in _IS_EQUAL_COMPONENT_RE.finditer(body)]
    if not equal_components:
        return False

    component_sides: dict[str, set[str]] = {component: set() for component in equal_components}
    component_in_re = {
        component: re.compile(rf"^{re.escape(component)}\.in\[[01]\]$") for component in equal_components
    }
    for match in _ASSIGN_RE.finditer(body):
        lhs = _compact(match.group("lhs"))
        rhs = _compact(match.group("rhs"))
        for component, pattern in component_in_re.items():
            if pattern.fullmatch(lhs):
                component_sides[component].add(rhs)
            if pattern.fullmatch(rhs):
                component_sides[component].add(lhs)

    for sides in component_sides.values():
        has_output_addr = any(
            any(re.search(rf"\b{re.escape(name)}\s*\[", side) for name in output_addr_names)
            for side in sides
        )
        has_input_addr = any(re.search(rf"\b{re.escape(input_addr)}\s*\[", side) for side in sides)
        if has_output_addr and has_input_addr and re.search(r"\b(?:sum|seen|matches|member)[A-Za-z_0-9]*\s*===\s*1\b", body, re.I):
            return True
    return False


def _output_addr_names(body: str) -> set[str]:
    declared = {match.group("name") for match in _DECLARED_OUTPUT_ADDR_RE.finditer(body)}
    mentioned = {match.group("name") for match in _OUTPUT_ADDR_RE.finditer(body)}
    return declared | mentioned


def erc20_sum_input_keyed_outflow_hits(source: str) -> list[dict[str, object]]:
    clean = _blank_comments(source)
    hits: list[dict[str, object]] = []

    for template_name, template_offset, template_source in _templates(clean):
        erc20_components = {match.group("name") for match in _COMPONENT_ARRAY_RE.finditer(template_source)}
        if not erc20_components:
            continue

        output_addr_names = _output_addr_names(template_source)
        for match in _INPUT_KEYED_ADDR_RE.finditer(template_source):
            outflow = match.group("outflow")
            idx = match.group("idx")
            input_addr = match.group("input_addr")
            if outflow not in erc20_components:
                continue
            if re.search(r"(?:outflow|output|withdraw)", outflow, re.I) is None:
                continue

            equality_re = re.compile(
                _OUTFLOW_EQUALITY_TEMPLATE.format(
                    idx=re.escape(idx),
                    outflow=re.escape(outflow),
                ),
                re.M,
            )
            if equality_re.search(template_source) is None:
                continue

            if _has_named_membership_guard(template_source):
                continue
            if _has_isequal_membership_guard(template_source, input_addr, output_addr_names):
                continue

            offset = template_offset + match.start()
            line, col = _line_col(source, offset)
            hits.append(
                {
                    "severity": "medium",
                    "line": line,
                    "col": col,
                    "template": template_name,
                    "outflow_component": outflow,
                    "input_addr": input_addr,
                    "message": (
                        f"{template_name} keys ERC20Sum outflow `{outflow}` by input token "
                        f"address array `{input_addr}` and equates only that keyed sum. "
                        "Unless every output token address is separately constrained to appear "
                        "in the input set, novel output token addresses can escape conservation."
                    ),
                    "snippet": source[offset : offset + 180].replace("\n", " "),
                }
            )
    return hits


def run_text(source: str, filepath: str = "<memory>") -> list[dict[str, object]]:
    return erc20_sum_input_keyed_outflow_hits(source)


def scan_file(path: Path) -> list[dict[str, object]]:
    return run_text(path.read_text(encoding="utf-8", errors="replace"), str(path))


def iter_circom_files(paths: Iterable[Path]) -> Iterable[Path]:
    for path in paths:
        if path.is_dir():
            yield from sorted(path.rglob("*.circom"))
        elif path.suffix == ".circom":
            yield path


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Detect input-keyed ERC20Sum outflow conservation checks in Circom.",
    )
    parser.add_argument("paths", nargs="+", type=Path, help="Circom files or directories to scan")
    parser.add_argument("--json", action="store_true", help="emit JSON hits")
    args = parser.parse_args(argv)

    hits: list[dict[str, object]] = []
    for path in iter_circom_files(args.paths):
        hits.extend(scan_file(path))

    if args.json:
        print(json.dumps(hits, indent=2, sort_keys=True))
    else:
        for hit in hits:
            print(f"{hit.get('line', 0)}:{hit.get('col', 0)}: {hit['severity']}: {hit['message']}")
    return 1 if hits else 0


if __name__ == "__main__":
    raise SystemExit(main())
