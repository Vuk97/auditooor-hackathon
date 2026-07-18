#!/usr/bin/env python3
"""
unconditional-ok-return-in-security-fn — CAP-BUILD-4 Rust detector.

Generalizes the OPSuccinct H6/H4 finding shape (`ismp-optimism/src/lib.rs`):

    pub fn verify_not_challenged(&self, _game: DisputeGameImpl) -> Result<()> {
        Ok(())
    }

A function whose name carries a security-relevant prefix
(``verify_``, ``validate_``, ``check_``, ``authorize_``, ``authenticate_``,
``assert_``, ``ensure_``, ``is_valid``) returns ``Ok(())`` / ``Ok(...)`` /
``true`` unconditionally with no branching, no comparisons, no
``return Err`` arm, and no early-exit guard. The function is a no-op
masquerading as a guard - the caller assumes it enforces an invariant
that the body never checks.

Pattern (positive / flagged):
  * Function name matches security-prefix regex.
  * Function body, after stripping comments and whitespace, is one of:
    - ``Ok(())``
    - ``Ok(<literal-or-simple-expr>)``
    - ``true``
    - ``return Ok(()) ;`` / ``return Ok(...) ;`` / ``return true ;``
  * No branching constructs (no ``if`` / ``match`` / ``while`` / ``for`` /
    ``loop``).
  * No error-returning calls (no ``return Err`` / ``?`` / ``bail!`` /
    ``ensure!`` / ``assert`` / ``debug_assert`` / ``.ok_or`` /
    ``.ok_or_else`` / ``.unwrap_or_else``).
  * Body is non-trivial: at least one statement (filters out empty
    trait-default stubs that legitimately return ``Ok(())`` with a
    ``todo!()`` or ``unimplemented!()`` body).

Pattern (negative / clean):
  * Body has any branching, any error-return path, any ``?`` operator,
  * Body delegates to another fn that performs the check
    (``self.inner.verify(...)`` / ``Self::do_verify(...)`` / etc.).
  * Body is a ``todo!()`` / ``unimplemented!()`` / ``unreachable!()``
    placeholder (intentional stub, not a fake guard).

Output line shape (matches other Rust detectors)::

    <file>:<line>:unconditional_ok_return_in_security_fn:<message>

Usage::

    python3 unconditional-ok-return-in-security-fn.py <path>
    # exit 0 always; hit signal communicated via stdout lines

Empirical anchor: Hyperbridge OPSuccinct `verify_not_challenged` returns
``Ok(())`` unconditionally for the ``DisputeGameImpl::OPSuccinct`` branch
(`ismp-optimism/src/lib.rs`). The caller assumes the challenge window was
honored; in fact no challenge state is read. Generalized as
``unconditional_ok_return_in_security_fn`` so other security guards that
silently pass-through are caught at scan time.

R36-rebuttal: build lane (CAP-BUILD-4); registered via
tools/agent-pathspec-register.py for the 4 files this lane writes.
"""
from __future__ import annotations

import argparse
import os
import re
import sys

DETECTOR_ID = "unconditional_ok_return_in_security_fn"

_SKIP_DIRS = {
    "target", ".git", "node_modules", "vendor", "_archive",
    ".idea", ".vscode", "third_party", "dist", "build", "out",
    ".auditooor",
}

# Security-relevant function-name prefixes. We anchor on the leading
# token so ``verify_inputs`` matches but ``deserialize_verifier`` does not.
_SECURITY_FN_NAME_RE = re.compile(
    r"^("
    r"verify(?:_[A-Za-z0-9_]+)?"
    r"|validate(?:_[A-Za-z0-9_]+)?"
    r"|check(?:_[A-Za-z0-9_]+)?"
    r"|authorize(?:_[A-Za-z0-9_]+)?"
    r"|authenticate(?:_[A-Za-z0-9_]+)?"
    r"|assert_[A-Za-z0-9_]+"
    r"|ensure_[A-Za-z0-9_]+"
    r"|is_valid(?:_[A-Za-z0-9_]+)?"
    r"|is_authorized(?:_[A-Za-z0-9_]+)?"
    r"|is_authenticated(?:_[A-Za-z0-9_]+)?"
    r")$"
)

# Rust fn header (visibility + async/const/unsafe + name + open paren).
_FN_HEADER_RE = re.compile(
    r"^[ \t]*"
    r"(?:pub(?:\s*\([^)]*\))?\s+)?"
    r"(?:async\s+|unsafe\s+|const\s+)*"
    r"fn\s+(?P<name>[A-Za-z_]\w*)"
    r"(?:\s*<[^(>]*>)?\s*\(",
)

# Branching / error-return / propagation markers that disqualify a fn
# from being treated as "unconditional Ok-return".
_BRANCHING_OR_ERROR_RE = re.compile(
    r"\bif\b"
    r"|\bmatch\b"
    r"|\bwhile\b"
    r"|\bfor\b"
    r"|\bloop\b"
    r"|\breturn\s+Err\b"
    r"|\bbail!\s*\("
    r"|\bensure!\s*\("
    r"|\bassert!\s*\("
    r"|\bassert_eq!\s*\("
    r"|\bassert_ne!\s*\("
    r"|\bdebug_assert!\s*\("
    r"|\bpanic!\s*\("
    r"|\bunwrap_or_else\s*\("
    r"|\bok_or\s*\("
    r"|\bok_or_else\s*\("
    # `?` operator: trailing question-mark on a method/field/call.
    r"|\)\s*\?(?:[ \t]|;|,|\)|\.|$)"
    r"|\]\s*\?(?:[ \t]|;|,|\)|\.|$)"
    r"|[A-Za-z_]\w*\s*\?(?:[ \t]|;|,|\)|\.|$)"
)

# Placeholder bodies we explicitly ignore. A `todo!()` or `unimplemented!()`
# stub is an honest "this is not implemented yet" signal, not a fake guard.
_PLACEHOLDER_RE = re.compile(
    r"\btodo!\s*\("
    r"|\bunimplemented!\s*\("
    r"|\bunreachable!\s*\("
)

# Delegation markers: if the fn body calls another verify/validate/check
# helper, the work is plausibly delegated. Suppress to avoid double-flag.
_DELEGATION_RE = re.compile(
    r"\bself\.[A-Za-z_]\w*\.(?:verify|validate|check|authorize|authenticate)"
    r"|\b[A-Za-z_]\w*::(?:verify|validate|check|authorize|authenticate)"
    r"|\b(?:verify|validate|check|authorize|authenticate)_[A-Za-z0-9_]+\s*\("
)

# Recognize the unconditional return body shapes. We strip comments and
# whitespace first, then check whether the body normalises to one of these.
_UNCONDITIONAL_OK_BODY_RE = re.compile(
    r"^\s*(?:return\s+)?Ok\s*\(\s*\(\s*\)\s*\)\s*;?\s*$"   # Ok(())
    r"|^\s*(?:return\s+)?Ok\s*\([^()]*\)\s*;?\s*$"          # Ok(<simple>)
    r"|^\s*(?:return\s+)?true\s*;?\s*$"                    # true
)


_LINE_COMMENT_RE = re.compile(r"//[^\n]*")
_BLOCK_COMMENT_RE = re.compile(r"/\*.*?\*/", re.DOTALL)


def _strip_comments(s: str) -> str:
    s = _BLOCK_COMMENT_RE.sub("", s)
    s = _LINE_COMMENT_RE.sub("", s)
    return s


# r36-rebuttal: build lane CAP-BUILD-4 - pathspec already registered via
# tools/agent-pathspec-register.py for the 4 files this lane writes.
def _normalize_body(body: str) -> str:
    """Strip comments + extract content inside the outer braces.

    The collector returns the line-range including the line that opens
    the body (which also contains ``fn name(params) {``) and the line
    that closes it. We must trim the header up to and including the
    FIRST ``{`` and the trailing ``}`` to expose just the body.
    """
    s = _strip_comments(body)
    first_brace = s.find("{")
    if first_brace >= 0:
        s = s[first_brace + 1:]
    last_brace = s.rfind("}")
    if last_brace >= 0:
        s = s[:last_brace]
    return s.strip()


def _collect_function_blocks(lines: list[str]) -> list[tuple[int, str, str]]:
    """Return list of (start_line_1indexed, fn_name, body_with_braces)."""
    results: list[tuple[int, str, str]] = []
    i = 0
    n = len(lines)
    while i < n:
        m = _FN_HEADER_RE.match(lines[i])
        if not m:
            i += 1
            continue
        fn_name = m.group("name")
        fn_start = i + 1  # 1-indexed
        brace_depth = 0
        body_start = None
        j = i
        found = False
        while j < n:
            line = lines[j]
            # Strip string literals and char literals so braces inside
            # them do not confuse the depth counter (lightweight pass).
            scan_line = re.sub(r'"([^"\\]|\\.)*"', '""', line)
            scan_line = re.sub(r"'([^'\\]|\\.)'", "''", scan_line)
            scan_line = re.sub(r"//.*$", "", scan_line)
            for ch in scan_line:
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
                        found = True
                        break
            if found:
                break
            # If we hit a ';' at depth 0 before any '{', it is a trait
            # fn signature (no body). Bail.
            if brace_depth == 0 and ";" in scan_line and body_start is None:
                break
            j += 1
        i += 1
    return results


def scan_file(filepath: str) -> list[tuple[int, str]]:
    """Return list of (line_1indexed, message) for a single .rs file."""
    try:
        with open(filepath, encoding="utf-8", errors="replace") as fh:
            content = fh.read()
    except OSError:
        return []

    lines = content.splitlines()
    hits: list[tuple[int, str]] = []
    for start_line, fn_name, body in _collect_function_blocks(lines):
        if not _SECURITY_FN_NAME_RE.match(fn_name):
            continue
        normalized = _normalize_body(body)
        if _PLACEHOLDER_RE.search(normalized):
            continue
        if _BRANCHING_OR_ERROR_RE.search(normalized):
            continue
        if _DELEGATION_RE.search(normalized):
            continue
        if not _UNCONDITIONAL_OK_BODY_RE.match(normalized):
            continue
        hits.append((
            start_line,
            f"fn `{fn_name}` is a security-named guard whose body "
            f"unconditionally returns Ok(())/Ok(<simple>)/true with no "
            f"branching, no `?` propagation, and no error path - "
            f"caller assumes invariant enforcement that the body never "
            f"performs (OPSuccinct verify_not_challenged shape).",
        ))
    return hits


def scan(root: str) -> list[tuple[str, int, str]]:
    """Walk a directory tree for .rs files and return (file, line, msg)."""
    results: list[tuple[str, int, str]] = []
    if os.path.isfile(root):
        for line, msg in scan_file(root):
            results.append((root, line, msg))
        return results
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
    p = argparse.ArgumentParser(
        description="Detect security-named Rust fns with unconditional Ok-return bodies",
    )
    p.add_argument("path", nargs="?", help="file or directory to scan for .rs sources")
    p.add_argument(
        "--list", action="store_true",
        help="print detector id and exit",
    )
    args = p.parse_args(argv)

    if args.list:
        print(DETECTOR_ID)
        return 0
    if not args.path:
        p.error("path argument required (or pass --list)")

    hits = scan(args.path)
    for fpath, line, msg in hits:
        print(f"{fpath}:{line}:{DETECTOR_ID}:{msg}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
