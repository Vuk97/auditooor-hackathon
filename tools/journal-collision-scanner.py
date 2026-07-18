#!/usr/bin/env python3
"""Flag contracts that use abi.encodePacked in >=2 different functions without
a leading domain-separator byte or function-selector prefix.

Base-Azul engagement-3 FN-3 shape (``AggregateVerifier.sol:548-602``): two code
paths (verifyProposalProof + nullify journal preimage) use abi.encodePacked
for semantically different operations. If a config value can make the two
schemas produce byte-identical output, a cross-operation collision trap-door
exists.

This is an advisory grep-grade scanner. Positives mean "investigate whether
these two preimages can collide at an N=1 boundary config" — not "confirmed
bug".
"""
from __future__ import annotations

import argparse
import json
import re
from pathlib import Path
from typing import Any


FUNCTION_RE = re.compile(
    r"\bfunction\s+([A-Za-z_][A-Za-z0-9_]*)\s*\("
)
CONTRACT_RE = re.compile(r"\bcontract\s+([A-Za-z_][A-Za-z0-9_]*)\b")
# Contract / library / abstract-contract header used to scope the
# >=2-functions check per-contract (Codex review #2 — file-wide
# aggregation produced FPs across unrelated contracts).
CONTRACT_HEADER_RE = re.compile(
    r"\b(?:abstract\s+)?(?:contract|library)\s+"
    r"([A-Za-z_][A-Za-z0-9_]*)\s*(?:is\s+[^{]*)?\{"
)

# Match any abi.encodePacked( or abi.encode( call; we'll look inside the
# argument list for a domain tag.
ENCODE_CALLS = ("abi.encodePacked", "abi.encode")

# A domain tag is one of:
#   * a bytes1/bytes4 literal (0x.. of length 2 or 8 hex chars) as the first
#     argument,
#   * a selector-style function-signature string ("FOO(...)"),
#   * a bytes32 constant whose name contains "TAG" / "DOMAIN" /
#     "SEPARATOR" / "SELECTOR" / "TYPEHASH" / "PREFIX" / "MAGIC",
#   * a keccak256(...) result of the same shape,
# placed in the FIRST argument slot of the encode call.
DOMAIN_TAG_FIRST_ARG_RE = re.compile(
    r"""^\s*(
        0x[0-9a-fA-F]{2,8}             # small bytes literal
        | "[A-Z][A-Za-z0-9_]*\([^"]*\)" # selector-style string
        | '[A-Z][A-Za-z0-9_]*\([^']*\)'
        | [A-Z_][A-Z0-9_]*(?:TAG|DOMAIN|SEPARATOR|SELECTOR|TYPEHASH|PREFIX|MAGIC)[A-Z0-9_]*
        | (?:this\.)?[A-Z_][A-Z0-9_]*(?:TAG|DOMAIN|SEPARATOR|SELECTOR|TYPEHASH|PREFIX|MAGIC)[A-Z0-9_]*
    )\s*(,|$)
    """,
    re.VERBOSE,
)


def _line_for_offset(source: str, offset: int) -> int:
    return source.count("\n", 0, offset) + 1


def _extract_balanced_arg(source: str, open_paren: int) -> str:
    depth = 0
    for idx in range(open_paren, len(source)):
        ch = source[idx]
        if ch == "(":
            depth += 1
        elif ch == ")":
            depth -= 1
            if depth == 0:
                return source[open_paren + 1 : idx]
    return ""


def _function_body_ranges(source: str, start: int = 0, end: int | None = None) -> list[tuple[str, int, int]]:
    """Return (name, start_offset, end_offset) for every function body
    delimited by `{...}` in the source slice ``[start:end]``. Naive
    brace-matching is OK for the regex-grade precision we need.

    The ``start``/``end`` window lets callers scope the walk to a single
    contract body (Codex review #2)."""
    if end is None:
        end = len(source)
    spans: list[tuple[str, int, int]] = []
    for fn_match in FUNCTION_RE.finditer(source, start, end):
        name = fn_match.group(1)
        # find the first `{` after the function signature header (still
        # inside the contract body)
        brace = source.find("{", fn_match.end(), end)
        if brace < 0:
            continue
        depth = 0
        body_end = -1
        for idx in range(brace, end):
            ch = source[idx]
            if ch == "{":
                depth += 1
            elif ch == "}":
                depth -= 1
                if depth == 0:
                    body_end = idx
                    break
        if body_end < 0:
            continue
        spans.append((name, brace, body_end))
    return spans


def _contract_bodies(source: str) -> list[tuple[str, int, int]]:
    """Return (name, body_start, body_end) for each contract / library
    body in the source. ``body_start`` points at the character AFTER the
    opening ``{`` and ``body_end`` at the matching ``}``. Manual
    brace-matching keeps the scanner stdlib-only.

    If the file has no contract header at all (e.g. a free-function-only
    .sol on newer compilers), we fall back to a single whole-file span so
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


def _encode_calls_in(source: str, start: int, end: int) -> list[tuple[int, str, str]]:
    """Return (offset, raw-arg-string, kind) for every abi.encode* call inside
    the given source slice.

    ``kind`` is ``"packed"`` for ``abi.encodePacked`` calls and ``"encode"`` for
    plain ``abi.encode`` calls. Callers that only want preimage-collision risk
    must filter to ``kind == "packed"`` — ``abi.encode`` is length-prefixed and
    not the collision shape this scanner targets (Codex review round 2, #117).

    Needles are searched in descending length order (``abi.encodePacked``
    first) and offsets already claimed by the longer needle are skipped so
    that ``abi.encodePacked`` is never double-counted as bare ``abi.encode``
    via substring match.
    """
    out: list[tuple[int, str, str]] = []
    seen_offsets: set[int] = set()
    # ENCODE_CALLS = ("abi.encodePacked", "abi.encode") — longest-first.
    for needle in ENCODE_CALLS:
        kind = "packed" if needle == "abi.encodePacked" else "encode"
        search_at = start
        token = needle + "("
        while True:
            idx = source.find(token, search_at, end)
            if idx < 0:
                break
            if idx in seen_offsets:
                # Substring overlap with abi.encodePacked — skip.
                search_at = idx + len(token)
                continue
            arg = _extract_balanced_arg(source, idx + len(needle))
            out.append((idx, arg, kind))
            seen_offsets.add(idx)
            search_at = idx + len(token)
    return out


def _has_domain_tag(arg: str) -> bool:
    # Strip leading whitespace/parens; ignore comments mid-argument.
    return DOMAIN_TAG_FIRST_ARG_RE.match(arg) is not None


def scan_file(path: Path) -> list[dict[str, Any]]:
    source = path.read_text(errors="replace")

    # Only look at sources that use abi.encodePacked at all; abi.encode
    # is included for completeness but the main risk class is encodePacked.
    if "abi.encodePacked" not in source:
        return []

    findings: list[dict[str, Any]] = []

    # Walk each contract body separately. The >=2-functions check has to
    # be PER-CONTRACT (Codex review #2): two unrelated contracts that each
    # contain a single tag-less encodePacked call do NOT constitute a
    # journal-collision risk against each other.
    for contract_name, body_start, body_end in _contract_bodies(source):
        risky_functions: list[dict[str, Any]] = []
        encode_context_functions: set[str] = set()
        for name, fn_start, fn_end in _function_body_ranges(source, body_start, body_end):
            calls = _encode_calls_in(source, fn_start, fn_end)
            # Codex review round 2 (#117 follow-up): only abi.encodePacked
            # counts toward the ">=2 distinct functions" trigger. abi.encode
            # is length-prefixed and NOT the preimage-collision shape, so a
            # single packedHelper() plus any number of safe abi.encode(...)
            # sites in the same contract must not fire the finding.
            packed_tagless_seen = False
            fn_has_any_encode = False
            for offset, arg, kind in calls:
                if kind == "encode":
                    # Track for reporter context only — never drives trigger.
                    fn_has_any_encode = True
                    continue
                # kind == "packed"
                tag_present = _has_domain_tag(arg.lstrip())
                if tag_present:
                    continue
                risky_functions.append(
                    {
                        "function": name,
                        "line": _line_for_offset(source, offset),
                    }
                )
                packed_tagless_seen = True
                break  # one tag-less packed call per function is enough

            # If the function didn't produce a tag-less-packed hit but DID
            # use abi.encode, list it as context so the submission body can
            # cite it without letting it drive the trigger.
            if fn_has_any_encode and not packed_tagless_seen:
                encode_context_functions.add(name)

        # Need >= 2 distinct functions with tag-less abi.encodePacked IN THE
        # SAME CONTRACT to produce a finding. abi.encode-only functions are
        # reporter context only.
        distinct = {r["function"]: r for r in risky_functions}
        if len(distinct) >= 2:
            finding = {
                "file": str(path),
                "contract": contract_name,
                "functions": sorted(distinct.keys()),
                "lines": sorted(r["line"] for r in distinct.values()),
                "pattern": "journal_collision_at_boundary_config",
                "severity": "advisory",
            }
            if encode_context_functions:
                finding["context_abi_encode_functions"] = sorted(
                    encode_context_functions
                )
            findings.append(finding)

    return findings


def main() -> int:
    parser = argparse.ArgumentParser(
        description=(
            "Advisory scanner for abi.encodePacked used across >=2 "
            "functions without a leading domain-separator tag."
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
                "{file}: {pattern}: contract {contract} uses tag-less "
                "encode in >=2 functions: {functions}".format(**finding)
            )

    return 1 if findings else 0


if __name__ == "__main__":
    raise SystemExit(main())
