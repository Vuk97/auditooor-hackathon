#!/usr/bin/env python3
"""Flag one-way boolean kill switches without recovery paths.

Base-Azul engagement-3 FN-6 shape (``Verifier.nullified`` at Verifier.sol:39-47):
a ``bool public <name>`` state variable whose only writes are ``<name> = true``
and whose contract (and the single-file view of this scanner) ships no
``<name> = false`` setter or ``un<Name>() / recover()`` path. Advisory-grade
grep scanner, not a full data-flow analysis.

Promote to HIGH when the flag gates value flow (the FN-6 case: nullify()
permanently disables the verifier).
"""
from __future__ import annotations

import argparse
import json
import re
from pathlib import Path
from typing import Any


BOOL_PUBLIC_RE = re.compile(
    r"\bbool\s+public\s+([A-Za-z_][A-Za-z0-9_]*)\s*(?:=\s*(?:true|false))?\s*;"
)
ASSIGN_TRUE_RE_TMPL = r"\b{name}\s*=\s*true\b"
ASSIGN_FALSE_RE_TMPL = r"\b{name}\s*=\s*false\b"

# Any helper that is plausibly a recovery path: setX, clearX, resetX, unX,
# recover*, disable*, reenable*. We look for a declaration or the literal
# assignment to false. Either proves the kill switch is NOT one-way from the
# view of the enclosing contract.
RECOVERY_NAME_RE_TMPL = (
    r"\bfunction\s+"
    r"(?:un{Name}|clear{Name}|reset{Name}|reenable{Name}|revive{Name}|"
    r"recover{Name}|disable{Name}|set{Name}|restore{Name})\s*\("
)

# Contract / library / interface / abstract-contract header. Detection has
# to be scoped to a single contract body — a sibling contract in the same
# .sol must not suppress findings on a vulnerable peer (Codex review #1).
CONTRACT_HEADER_RE = re.compile(
    r"\b(?:abstract\s+)?(?:contract|library|interface)\s+"
    r"([A-Za-z_][A-Za-z0-9_]*)\s*(?:is\s+[^{]*)?\{"
)


def _line_for_offset(source: str, offset: int) -> int:
    return source.count("\n", 0, offset) + 1


def _camel(name: str) -> str:
    """Title-case the variable name for function-name matching."""
    if not name:
        return name
    return name[:1].upper() + name[1:]


def _contains(source: str, regex: str) -> bool:
    return re.search(regex, source) is not None


def _contract_bodies(source: str) -> list[tuple[str, int, int]]:
    """Return (name, body_start, body_end) for each contract / library /
    interface body in the source. ``body_start`` points at the character
    AFTER the opening ``{`` and ``body_end`` at the matching ``}``. Manual
    brace-matching keeps the scanner stdlib-only (no new deps).

    If the file ships no contract header at all (a free-function-only .sol
    on newer compilers), we fall back to a single whole-file span so
    behaviour matches the pre-fix scanner for that edge case.
    """
    bodies: list[tuple[str, int, int]] = []
    for match in CONTRACT_HEADER_RE.finditer(source):
        name = match.group(1)
        open_brace = match.end() - 1  # the `{` captured by the header regex
        depth = 0
        end = -1
        for idx in range(open_brace, len(source)):
            ch = source[idx]
            if ch == "{":
                depth += 1
            elif ch == "}":
                depth -= 1
                if depth == 0:
                    end = idx
                    break
        if end < 0:
            continue
        bodies.append((name, open_brace + 1, end))
    if not bodies:
        bodies.append(("<file>", 0, len(source)))
    return bodies


def scan_file(path: Path) -> list[dict[str, Any]]:
    source = path.read_text(errors="replace")
    findings: list[dict[str, Any]] = []

    for contract_name, body_start, body_end in _contract_bodies(source):
        body = source[body_start:body_end]

        for match in BOOL_PUBLIC_RE.finditer(body):
            name = match.group(1)

            assign_true_re = ASSIGN_TRUE_RE_TMPL.format(name=re.escape(name))
            assign_false_re = ASSIGN_FALSE_RE_TMPL.format(name=re.escape(name))
            recovery_re = RECOVERY_NAME_RE_TMPL.format(Name=re.escape(_camel(name)))

            # Must actually be written to true somewhere in THIS contract
            # body; else it's just a flag that external callers set via
            # some other pattern not covered here.
            if not _contains(body, assign_true_re):
                continue

            # If there is ANY `<name> = false` OR a plausibly-named recovery
            # function IN THIS CONTRACT, the kill switch is not one-way.
            # Sibling contracts in the same .sol must NOT suppress us
            # (Codex review #1 — file-wide recovery detection was a FN).
            if _contains(body, assign_false_re):
                continue
            if _contains(body, recovery_re):
                continue

            findings.append(
                {
                    "file": str(path),
                    "contract": contract_name,
                    "line": _line_for_offset(source, body_start + match.start(1)),
                    "variable": name,
                    "pattern": "one_way_kill_switch_no_recovery",
                    "severity": "advisory",
                }
            )

    return findings


def main() -> int:
    parser = argparse.ArgumentParser(
        description=(
            "Advisory scanner for one-way bool public kill switches that "
            "never get reset or recovered."
        )
    )
    parser.add_argument("paths", nargs="+", type=Path, help="Solidity files or directories")
    parser.add_argument("--json", action="store_true", help="Emit JSON findings")
    args = parser.parse_args()

    files: list[Path] = []
    for path in args.paths:
        if path.is_dir():
            files.extend(sorted(path.rglob("*.sol")))
        elif path.suffix == ".sol":
            files.append(path)

    findings: list[dict[str, Any]] = []
    for file_path in files:
        findings.extend(scan_file(file_path))

    if args.json:
        print(json.dumps({"findings": findings}, indent=2))
    else:
        for finding in findings:
            print(
                "{file}:{line}: {pattern}: bool public {variable} is only "
                "written to true with no recovery path".format(**finding)
            )

    return 1 if findings else 0


if __name__ == "__main__":
    raise SystemExit(main())
