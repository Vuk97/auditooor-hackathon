"""
base64decodedlength_unconstrained_output.py

Candidate-specific Circom detector for zkBugs survivor:
  circom__under-constrained__base64decodedlength-output-is-declared-but-never-constrained

Flags Base64DecodedLength/Base64UrlDecodedLength templates whose
`signal output decoded_len` is declared but never directly constrained with
`<==` or `===` in the uncommented template body. The historical vulnerable
shape declared `decoded_len`, constrained only quotient/remainder helper
signals, and left the intended `decoded_len <== q` line commented out.

This is intentionally narrow to avoid turning a single survivor into a noisy
generic Circom unconstrained-output detector.
"""

from __future__ import annotations

import argparse
import json
import re
from dataclasses import dataclass
from pathlib import Path
from typing import Iterable


TARGET_TEMPLATES = {"Base64DecodedLength", "Base64UrlDecodedLength"}
TARGET_OUTPUT = "decoded_len"

_LINE_COMMENT_RE = re.compile(r"//[^\n]*")
_BLOCK_COMMENT_RE = re.compile(r"/\*.*?\*/", re.DOTALL)
_TEMPLATE_RE = re.compile(
    r"\btemplate\s+(?P<name>[A-Za-z_]\w*)\s*(?:\([^)]*\))?\s*\{",
    re.MULTILINE,
)
_OUTPUT_DECL_RE = re.compile(r"\bsignal\s+output\s+(?P<decl>[^;]+);")


@dataclass(frozen=True)
class Hit:
    filepath: str
    line: int
    template: str
    output: str
    message: str

    def as_dict(self) -> dict[str, object]:
        return {
            "severity": "high",
            "filepath": self.filepath,
            "line": self.line,
            "template": self.template,
            "output": self.output,
            "message": self.message,
        }


def _blank_comments(source: str) -> str:
    """Remove comments while preserving byte-ish offsets and line numbers."""

    def blank(match: re.Match[str]) -> str:
        text = match.group(0)
        return "".join("\n" if ch == "\n" else " " for ch in text)

    source = _BLOCK_COMMENT_RE.sub(blank, source)
    source = _LINE_COMMENT_RE.sub(blank, source)
    return source


def _matching_brace(source: str, open_brace: int) -> int | None:
    depth = 0
    for idx in range(open_brace, len(source)):
        ch = source[idx]
        if ch == "{":
            depth += 1
        elif ch == "}":
            depth -= 1
            if depth == 0:
                return idx
    return None


def _line_at(source: str, offset: int) -> int:
    return source.count("\n", 0, offset) + 1


def _declares_target_output(statement_tail: str) -> bool:
    # Handles `signal output decoded_len;`,
    # `signal output decoded_len <== q;`, and array syntax if encountered.
    return re.match(rf"\s*{re.escape(TARGET_OUTPUT)}\b", statement_tail) is not None


def _output_is_constrained(body: str, output: str) -> bool:
    ident = re.escape(output)
    assignment = re.compile(rf"\b{ident}\b(?:\s*\[[^\]]+\])?\s*<==")
    equality_lhs = re.compile(rf"\b{ident}\b(?:\s*\[[^\]]+\])?\s*===")
    equality_rhs = re.compile(rf"===\s*\b{ident}\b(?:\s*\[[^\]]+\])?")
    return any(pattern.search(body) for pattern in (assignment, equality_lhs, equality_rhs))


def scan_text(source: str, filepath: str = "<memory>") -> list[dict[str, object]]:
    clean = _blank_comments(source)
    hits: list[Hit] = []

    for match in _TEMPLATE_RE.finditer(clean):
        template_name = match.group("name")
        if template_name not in TARGET_TEMPLATES:
            continue

        open_brace = clean.find("{", match.start())
        close_brace = _matching_brace(clean, open_brace)
        if close_brace is None:
            continue

        body = clean[open_brace + 1:close_brace]
        body_start = open_brace + 1
        for decl_match in _OUTPUT_DECL_RE.finditer(body):
            decl = decl_match.group("decl")
            if not _declares_target_output(decl):
                continue
            if _output_is_constrained(body, TARGET_OUTPUT):
                continue
            line = _line_at(clean, body_start + decl_match.start())
            hits.append(Hit(
                filepath=filepath,
                line=line,
                template=template_name,
                output=TARGET_OUTPUT,
                message=(
                    f"{template_name} declares `signal output {TARGET_OUTPUT}` "
                    "but never directly constrains it with `<==` or `===`; "
                    "callers can treat the decoded payload length as prover-chosen."
                ),
            ))

    return [hit.as_dict() for hit in hits]


def scan_file(path: Path) -> list[dict[str, object]]:
    return scan_text(path.read_text(encoding="utf-8", errors="replace"), str(path))


def run_text(source: str, filepath: str) -> list[dict[str, object]]:
    return scan_text(source, filepath)


def iter_circom_files(paths: Iterable[Path]) -> Iterable[Path]:
    for path in paths:
        if path.is_dir():
            yield from sorted(path.rglob("*.circom"))
        elif path.suffix == ".circom":
            yield path


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Detect unconstrained decoded_len output in Base64DecodedLength Circom templates.",
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
            print(
                f"{hit['filepath']}:{hit['line']}: "
                f"{hit['severity']}: {hit['message']}"
            )
    return 1 if hits else 0


if __name__ == "__main__":
    raise SystemExit(main())
