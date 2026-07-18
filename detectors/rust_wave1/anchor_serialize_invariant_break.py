"""
anchor_serialize_invariant_break.py

Detects silent serialization failures in Anchor programs.

`try_to_vec()` and `try_serialize()` return `Result` - if the result is
ignored (`let _ = account.try_to_vec()` or the return value is discarded),
the program continues with stale on-chain state while thinking it wrote
updated data.  This breaks account-state invariants silently.

Similarly, `AnchorSerialize::try_serialize` failure (e.g. due to buffer
size mismatch) can leave account data in an intermediate state.

Bug class: HIGH (state corruption / invariant break via silent serialization failure)
Platform:  Solana / Anchor
Empirical anchor: OtterSec serialization-related account invariant breaks;
                  CyfrinM accounts-may-be-created-with-incorrect-rent-exemption class.

Algorithm (regex):
1. Find `try_to_vec()` / `try_serialize()` / `serialize()` calls NOT followed
   by `?` or `.unwrap()` or `match` / `if let` error handling.
2. Flag any occurrence where the return value is discarded:
   - `let _ = x.try_to_vec();`
   - `x.try_to_vec();` (result unused, not propagated with `?`)
3. Safe patterns: `x.try_to_vec()?`, `x.try_to_vec().unwrap()`,
   `match x.try_to_vec() { Ok(...) => ... Err(...) => ... }`,
   `if let Ok(...) = x.try_to_vec()`.
"""
from __future__ import annotations

import os
import pathlib
import re
import sys
from typing import Optional

DETECTOR_ID = "rust_wave1.anchor_serialize_invariant_break"

_SKIP_DIRS = {"target", ".git", "node_modules", "vendor", "_archive"}

# Serialization calls - match the full call expression
_SERIALIZE_CALL_RE = re.compile(
    r"(?P<expr>\w[\w.]*)\s*\.\s*"
    r"(?P<method>try_to_vec|try_serialize|serialize)\s*\(\s*(?P<args>[^)]*)\)"
    r"(?P<suffix>[^;\n]*)"
    r"(?P<terminator>[;\n])"
)

# Propagation suffixes that make this safe
_SAFE_SUFFIX_RE = re.compile(r"[?]|\bunwrap\b|\bexpect\b|\bmatch\b")

_FN_HEADER_RE = re.compile(
    r"^[ \t]*"
    r"(?:pub(?:\s*\([^)]*\))?\s+)?"
    r"(?:unsafe\s+|const\s+|async\s+)*"
    r"fn\s+(?P<name>[A-Za-z_]\w*)"
    r"(?:\s*<[^(>]*>)?\s*\(",
    re.MULTILINE,
)

_TEST_RE = re.compile(r"#\[\s*(?:cfg\s*\(\s*test|test)\s*\]")


def _extract_fn_body(content: str, fn_start: int) -> tuple[Optional[str], int]:
    depth = 0
    body_start: Optional[int] = None
    i = fn_start
    while i < len(content):
        ch = content[i]
        if ch == "{":
            depth += 1
            if depth == 1:
                body_start = i + 1
        elif ch == "}":
            depth -= 1
            if depth == 0 and body_start is not None:
                return content[body_start:i], content[:fn_start].count("\n") + 1
        i += 1
    return None, 0


def scan_file(filepath: str) -> list[dict]:
    try:
        with open(filepath, encoding="utf-8", errors="replace") as fh:
            content = fh.read()
    except OSError:
        return []

    if "try_to_vec" not in content and "try_serialize" not in content:
        return []

    if "anchor_lang" not in content and "solana_program" not in content and "borsh" not in content:
        return []

    fp = pathlib.Path(filepath)
    _crate_name: Optional[str] = None
    _mod_prefix = ""
    try:
        _DETECTOR_DIR = pathlib.Path(__file__).resolve().parent
        if str(_DETECTOR_DIR) not in sys.path:
            sys.path.insert(0, str(_DETECTOR_DIR))
        from _util import crate_name_from_path as _cnfp, _file_module_prefix
        _crate_name = _cnfp(fp)
        _mod_prefix = _file_module_prefix(fp)
    except Exception:
        pass

    hits = []

    for m_fn in _FN_HEADER_RE.finditer(content):
        fn_name_val = m_fn.group("name")
        fn_offset = m_fn.start()
        fn_line = content[:fn_offset].count("\n") + 1

        surrounding = content[max(0, fn_offset - 200):fn_offset]
        if _TEST_RE.search(surrounding):
            continue

        body, _ = _extract_fn_body(content, fn_offset)
        if body is None:
            continue

        for m in _SERIALIZE_CALL_RE.finditer(body):
            suffix = m.group("suffix")
            method = m.group("method")

            # Safe if result is propagated with `?`, `unwrap`, `expect`
            if _SAFE_SUFFIX_RE.search(suffix):
                continue

            # Check what comes BEFORE the call on the same line
            before_match = body[:m.start()]
            line_start = before_match.rfind("\n") + 1
            line_text = before_match[line_start:]

            # Safe if `match` precedes the call on the same line
            if re.search(r"\bmatch\b", line_text):
                continue

            # Safe if the call is the scrutinee of `if let`
            if re.search(r"\bif\s+let\b", line_text):
                continue

            # let _ = ... pattern → definitely discarded
            if re.search(r"let\s+_\s*=", line_text):
                pass  # fall through to flag
            # let var = ... pattern → variable might be checked later
            elif re.search(r"let\s+\w+\s*=", line_text):
                # Look ahead for match/if let on the variable
                after = body[m.end():m.end() + 200]
                if re.search(r"\b(match|if\s+let|\.is_err\(\)|\.is_ok\(\))\b", after):
                    continue  # safe - result handled
            # Bare call with no assignment → result discarded
            else:
                pass  # fall through to flag

            call_line = fn_line + body[:m.start()].count("\n")

            h: dict = {
                "detector_id": DETECTOR_ID,
                "file": filepath,
                "line": fn_line,
                "fn_name": fn_name_val,
                "call_line": call_line,
                "method": method,
                "severity": "HIGH",
                "message": (
                    f"fn `{fn_name_val}`: `{method}()` result at line {call_line} "
                    f"not propagated with `?` / `unwrap` / `match` - "
                    f"silent serialization failure leaves account state inconsistent."
                ),
            }
            if _crate_name and _crate_name != "unknown":
                h["crate_name"] = _crate_name
            if _mod_prefix:
                h["module_path"] = _mod_prefix
            hits.append(h)

    return hits


def scan(root: str) -> list[tuple[str, int, str]]:
    results = []
    for dirpath, dirnames, filenames in os.walk(root):
        dirnames[:] = [d for d in dirnames if d not in _SKIP_DIRS]
        for fname in filenames:
            if not fname.endswith(".rs"):
                continue
            fpath = os.path.join(dirpath, fname)
            for h in scan_file(fpath):
                results.append((h["file"], h["line"], h["message"]))
    return results


def run(tree, source_bytes, filepath: str, *, engine=None) -> list[dict]:
    return scan_file(filepath)


if __name__ == "__main__":
    root = sys.argv[1] if len(sys.argv) > 1 else "."
    for fpath, line, msg in scan(root):
        print(f"{fpath}:{line}:{DETECTOR_ID}:{msg}")
