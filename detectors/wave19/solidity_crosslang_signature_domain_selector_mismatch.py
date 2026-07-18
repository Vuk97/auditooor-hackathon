"""
solidity-crosslang-signature-domain-selector-mismatch - Wave-19 cross-language lift.

Rust to Solidity replay-domain invariant:
if a signed payload carries a selector-like domain field, the verifier must bind
that field to the runtime entrypoint that consumes the signature. Otherwise the
same signature can replay across ABI-compatible sibling functions that share the
verifier but perform different state transitions.

This detector is intentionally narrow:
1. Find verifier-like functions that contain signature recovery plus
   `keccak256(abi.encode(... selector ...))`.
2. Require that the verifier body does NOT bind the signed selector to
   `msg.sig`, `this.<fn>.selector`, or calldata selector bytes.
3. Require at least 2 public/external callers to the same verifier helper.

That keeps the detector focused on replay-across-entrypoint shapes rather than
generic EIP-712 usage.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import List


DETECTOR_NAME = "solidity-crosslang-signature-domain-selector-mismatch"


@dataclass
class Finding:
    detector: str
    file: str
    line: int
    severity: str
    message: str
    function: str | None = None


_BLOCK_COMMENT_RE = re.compile(r"/\*.*?\*/", re.DOTALL)
_LINE_COMMENT_RE = re.compile(r"//[^\n]*")
_FUNCTION_HEADER_RE = re.compile(
    r"\bfunction\s+([A-Za-z_][A-Za-z0-9_]*)\s*\([^)]*\)\s*([^{};]*)\{",
    re.DOTALL,
)
_VERIFY_RE = re.compile(r"\b(?:ecrecover|ECDSA\s*\.\s*recover|SignatureChecker)\b")
_ENCODE_SELECTOR_RE = re.compile(r"\babi\.encode(?:Packed)?\b", re.IGNORECASE)
_SELECTOR_TOKEN_RE = re.compile(
    r"\b(?:[A-Za-z_][A-Za-z0-9_]*\.)?"
    r"(?:selector|functionSelector|actionSelector|callSelector)\b"
)
_RUNTIME_BINDING_RE = re.compile(
    r"\bmsg\.sig\b|"
    r"\bthis\s*\.\s*[A-Za-z_][A-Za-z0-9_]*\s*\.\s*selector\b|"
    r"\bbytes4\s*\(\s*msg\.sig\s*\)|"
    r"\bcalldataload\s*\(\s*0\s*\)",
    re.IGNORECASE,
)
_VISIBILITY_RE = re.compile(r"\b(public|external)\b")


@dataclass
class _FunctionBlock:
    name: str
    header: str
    body: str
    start: int
    line: int

    @property
    def is_public_entry(self) -> bool:
        return _VISIBILITY_RE.search(self.header) is not None


def _strip_comments(source: str) -> str:
    return _LINE_COMMENT_RE.sub("", _BLOCK_COMMENT_RE.sub("", source))


def _extract_functions(source: str) -> list[_FunctionBlock]:
    out: list[_FunctionBlock] = []
    for match in _FUNCTION_HEADER_RE.finditer(source):
        name = match.group(1)
        header = match.group(0)
        body_start = match.end() - 1
        depth = 0
        end = None
        for idx in range(body_start, len(source)):
            ch = source[idx]
            if ch == "{":
                depth += 1
            elif ch == "}":
                depth -= 1
                if depth == 0:
                    end = idx
                    break
        if end is None:
            continue
        block = source[match.start() : end + 1]
        out.append(
            _FunctionBlock(
                name=name,
                header=header,
                body=block,
                start=match.start(),
                line=source.count("\n", 0, match.start()) + 1,
            )
        )
    return out


def _is_selector_domain_verifier(fn: _FunctionBlock) -> bool:
    return (
        _VERIFY_RE.search(fn.body) is not None
        and _ENCODE_SELECTOR_RE.search(fn.body) is not None
        and "keccak256" in fn.body
        and _SELECTOR_TOKEN_RE.search(fn.body) is not None
        and _RUNTIME_BINDING_RE.search(fn.body) is None
    )


def _caller_names(target: _FunctionBlock, functions: list[_FunctionBlock]) -> list[str]:
    call_re = re.compile(rf"\b{re.escape(target.name)}\s*\(")
    callers: list[str] = []
    for fn in functions:
        if fn.name == target.name or not fn.is_public_entry:
            continue
        if call_re.search(fn.body):
            callers.append(fn.name)
    return callers


def scan(source: str, file_path: str = "<unknown>") -> List[Finding]:
    stripped = _strip_comments(source)
    functions = _extract_functions(stripped)
    findings: list[Finding] = []

    for fn in functions:
        if not _is_selector_domain_verifier(fn):
            continue
        callers = _caller_names(fn, functions)
        if len(callers) < 2:
            continue
        findings.append(
            Finding(
                detector=DETECTOR_NAME,
                file=file_path,
                line=fn.line,
                severity="High",
                function=fn.name,
                message=(
                    "Signature verifier hashes a selector-like domain field but never "
                    "binds it to the runtime entrypoint. Multiple public callers share "
                    f"`{fn.name}()` ({', '.join(callers)}), so the same signature can "
                    "replay across ABI-compatible actions unless the signed selector is "
                    "checked against msg.sig or a concrete function.selector."
                ),
            )
        )

    return findings


__all__ = ["scan", "Finding", "DETECTOR_NAME"]
