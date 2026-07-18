#!/usr/bin/env python3
"""
frost_keypackage_serialization_unauthenticated — wave-2 FROST detector.

Detects ``KeyPackage::deserialize`` (or ``bincode::deserialize``,
``serde_json::from_slice``, etc.) call sites that load a KeyPackage from bytes
without verifying that the deserialized key package matches a trusted
``PublicKeyPackage`` digest.  Without this check an attacker who can write the
serialized bytes can swap in a different signing share, performing a key-rotation
replay without authorization.

Pattern (positive / flagged):
  * A function body contains a ``KeyPackage::deserialize`` / ``from_bytes`` /
    ``bincode::deserialize`` / ``serde_json::from_slice`` call that binds the
    result to a variable (``let kp`` / ``let key_package`` / similar).
  * The same body does NOT call ``verify_pubkey_package`` / ``verify_digest`` /
    ``pubkey_package.verify`` / ``check_key_package_digest`` / a similar
    digest-verification helper.

Pattern (negative / clean):
  * A digest-verification call is present before (or after) the deserialize.

Usage::

    python3 frost_keypackage_serialization_unauthenticated.py <path>

Outputs one line per hit::

    <file>:<line>:frost_keypackage_serialization_unauthenticated:<message>

Exit 0 always.
"""
from __future__ import annotations

import os
import re
import sys

DETECTOR_ID = "frost_keypackage_serialization_unauthenticated"

_SKIP_DIRS = {"target", ".git", "node_modules", "vendor", "_archive"}

_FN_HEADER_RE = re.compile(
    r"^[ \t]*"
    r"(?:pub(?:\s*\([^)]*\))?\s+)?"
    r"(?:async\s+|unsafe\s+|const\s+)*"
    r"fn\s+(?P<name>[A-Za-z_]\w*)"
    r"(?:\s*<[^(>]*>)?\s*\(",
)

# Deserialization call producing a KeyPackage.
# We match on:
#   KeyPackage::deserialize(
#   KeyPackage::from_bytes(
#   bincode::deserialize::<KeyPackage
#   serde_json::from_slice::<KeyPackage
#   let kp: KeyPackage = ...
#   let key_package: KeyPackage = ...
_KEYPACKAGE_DESER_RE = re.compile(
    r"\bKeyPackage\s*::\s*(?:deserialize|from_bytes)\s*\("
    r"|\bbincode\s*::\s*deserialize\s*::<\s*KeyPackage"
    r"|\bserde_json\s*::\s*from_slice\s*::<\s*KeyPackage"
    r"|\bserde_json\s*::\s*from_reader\s*::<\s*KeyPackage"
    r"|let\s+\w+\s*:\s*KeyPackage\s*[=<]"
)

# Digest-verification guard: any of these indicates the author authenticates
# the deserialized KeyPackage.
_DIGEST_GUARD_RE = re.compile(
    r"\bverify_pubkey_package\s*\("
    r"|\bverify_pubkey_package_digest\s*\("
    r"|\bpubkey_package\s*\.\s*verify\s*\("
    r"|\bcheck_key_package_digest\s*\("
    r"|\bkey_package_digest\s*\("
    r"|\bverify_key_package\s*\("
    r"|\bexpected_digest\b"
    r"|\bdigest_matches\b"
    r"|\bcompare_digest\s*\("
)


def _collect_function_blocks(lines: list[str]) -> list[tuple[int, str, str]]:
    results = []
    i = 0
    n = len(lines)
    while i < n:
        m = _FN_HEADER_RE.match(lines[i])
        if m:
            fn_name = m.group("name")
            fn_start = i + 1
            brace_depth = 0
            body_start = None
            j = i
            while j < n:
                for ch in lines[j]:
                    if ch == "{":
                        if brace_depth == 0:
                            body_start = j
                        brace_depth += 1
                    elif ch == "}":
                        brace_depth -= 1
                        if brace_depth == 0 and body_start is not None:
                            body = "\n".join(lines[body_start:j + 1])
                            results.append((fn_start, fn_name, body))
                            i = j
                            break
                else:
                    j += 1
                    continue
                break
        i += 1
    return results


def scan_file(filepath: str) -> list[tuple[int, str]]:
    try:
        with open(filepath, encoding="utf-8", errors="replace") as fh:
            content = fh.read()
    except OSError:
        return []

    lines = content.splitlines()
    hits = []
    for start_line, fn_name, body in _collect_function_blocks(lines):
        if not _KEYPACKAGE_DESER_RE.search(body):
            continue
        if _DIGEST_GUARD_RE.search(body):
            continue
        # Skip tiny stubs.
        if body.count("\n") < 2:
            continue
        hits.append((
            start_line,
            f"fn `{fn_name}` deserializes a KeyPackage without verifying a "
            f"pubkey-package digest — key-rotation replay possible.",
        ))
    return hits


def scan(root: str) -> list[tuple[str, int, str]]:
    results = []
    for dirpath, dirnames, filenames in os.walk(root):
        dirnames[:] = [d for d in dirnames if d not in _SKIP_DIRS]
        for fname in filenames:
            if not fname.endswith(".rs"):
                continue
            fpath = os.path.join(dirpath, fname)
            for line, msg in scan_file(fpath):
                results.append((fpath, line, msg))
    return results


def main(argv: list[str] | None = None) -> int:
    args = argv if argv is not None else sys.argv[1:]
    if not args:
        print(f"usage: {sys.argv[0]} <path>", file=sys.stderr)
        return 2
    root = args[0]
    hits = scan(root)
    for fpath, line, msg in hits:
        print(f"{fpath}:{line}:{DETECTOR_ID}:{msg}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
