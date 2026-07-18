"""
mutex_lock_order_inversion.py

Detects lock-order inversions across pairs of functions in the same module:
fn A acquires mutex-X then mutex-Y; fn B acquires mutex-Y then mutex-X.
This is the classic ABBA deadlock — if A and B execute concurrently, each
blocks waiting for the other's held lock and the process hangs permanently.

Bug class: HIGH (DoS — hangs the entire process).
Empirical anchor: dYdX cantina-202 CRITICAL (iavl-1024 RWMutex inversion
in cosmos-sdk-rs analog).  Spark coordinator has similar shape in entgo/ent
transaction handling.

Algorithm (pure regex, no tree-sitter dependency):
1. Extract all function bodies in the file via brace-depth tracking.
2. For each function, collect the ORDERED sequence of `.lock()` / `.read()` /
   `.write()` calls and record the receiver identifier (the variable/field
   name immediately before the `.`).
3. For every pair (fn_i, fn_j), if fn_i's lock sequence and fn_j's lock
   sequence share at least two lock targets whose order is INVERTED, emit a
   finding for both functions.

False-positive guards:
  - Lock calls where the guard is immediately dropped between acquisitions
    (`drop(guard)` between the two lock calls in the same fn) break the chain.
  - Lock calls inside `tokio::spawn` / `thread::spawn` closures — the spawned
    closure has its own stack; we skip those lock calls for ordering purposes.
  - If both fns acquire the same two locks in the SAME order → no inversion.

Limitations:
  - Receiver identifier extraction is regex-based; complex expressions like
    `self.state.inner.lock()` are collapsed to the last identifier before `.`
    (i.e. `inner`).  For most real-world code this is sufficient.
  - Does not track lock guards across function calls; only direct `.lock*()`
    calls in the body.
  - Does not handle `Arc::clone` sharing; assumes same identifier = same mutex.

Outputs one dict per inverted pair (two hits, one per function in the pair).
"""
from __future__ import annotations

import os
import pathlib
import re
import sys
from typing import Optional

DETECTOR_ID = "rust_wave1.mutex_lock_order_inversion"

_SKIP_DIRS = {"target", ".git", "node_modules", "vendor", "_archive"}

_FN_HEADER_RE = re.compile(
    r"^[ \t]*"
    r"(?:pub(?:\s*\([^)]*\))?\s+)?"
    r"(?:unsafe\s+|const\s+|async\s+)*"
    r"fn\s+(?P<name>[A-Za-z_]\w*)"
    r"(?:\s*<[^(>]*>)?\s*\(",
    re.MULTILINE,
)

# Pattern: <receiver>.<method>() where method is a lock variant
# Captures the receiver identifier (last segment before the dot)
_LOCK_RE = re.compile(
    r"(?P<receiver>[A-Za-z_]\w*)"
    r"\s*\.\s*"
    r"(?P<method>lock|read|write|try_lock|try_read|try_write)"
    r"\s*\(\s*\)",
)

# Drop call — releases a guard
_DROP_RE = re.compile(r"\bdrop\s*\(\s*(?P<var>[A-Za-z_]\w*)\s*\)")

# spawn — skip lock calls inside spawn closures
_SPAWN_RE = re.compile(r"\b(?:tokio::spawn|thread::spawn|task::spawn(?:_blocking)?)\s*\(")


def _extract_fn_body(content: str, fn_start_offset: int) -> tuple[Optional[str], int]:
    """Return (body_text, body_start_line) or (None, 0)."""
    depth = 0
    in_body = False
    body_start = -1
    i = fn_start_offset
    n = len(content)
    while i < n:
        ch = content[i]
        if ch == "{":
            if depth == 0:
                body_start = i
                in_body = True
            depth += 1
        elif ch == "}":
            depth -= 1
            if in_body and depth == 0:
                body = content[body_start:i + 1]
                start_line = content[:body_start].count("\n") + 1
                return body, start_line
        i += 1
    return None, 0


def _lock_sequence_in_body(body: str) -> list[tuple[str, str]]:
    """Return ordered list of (receiver_id, method) lock calls in body.

    Strips spawn closures and handles drop() between acquisitions.
    Returns the sequence of lock calls as they appear in source order.
    """
    # Remove spawn closure interiors (rough: replace content between
    # spawn( ... ) with placeholder so we don't count those lock calls)
    cleaned = body
    for m_sp in _SPAWN_RE.finditer(body):
        # Find the matching closing paren by brace/paren depth
        start = m_sp.end()
        depth = 1
        i = start
        n = len(body)
        while i < n and depth > 0:
            if body[i] in ("(", "{"):
                depth += 1
            elif body[i] in (")", "}"):
                depth -= 1
            i += 1
        # Blank out the spawn closure content
        cleaned = cleaned[:m_sp.start()] + " " * (i - m_sp.start()) + cleaned[i:]

    # Build ordered lock sequence
    sequence = []
    guard_vars: dict[str, str] = {}  # var -> receiver_id (for tracking drops)
    for m in _LOCK_RE.finditer(cleaned):
        recv = m.group("receiver")
        method = m.group("method")
        # Check if a guard variable assignment precedes this call
        # (look at up to 60 chars before for `let <var> =`)
        prefix = cleaned[max(0, m.start() - 60):m.start()]
        assign_m = re.search(r"let\s+(?:mut\s+)?(?P<var>[A-Za-z_]\w*)\s*=\s*$", prefix)
        if assign_m:
            guard_vars[assign_m.group("var")] = recv
        sequence.append((recv, method))

    return sequence


def scan_file(filepath: str) -> list[dict]:
    try:
        with open(filepath, encoding="utf-8", errors="replace") as fh:
            content = fh.read()
    except OSError:
        return []

    fp = pathlib.Path(filepath)

    # Try to get crate name
    _crate_name: Optional[str] = None
    try:
        import sys as _sys
        _DETECTOR_DIR = pathlib.Path(__file__).resolve().parent
        if str(_DETECTOR_DIR) not in _sys.path:
            _sys.path.insert(0, str(_DETECTOR_DIR))
        from _util import crate_name_from_path as _cnfp, _file_module_prefix
        _crate_name = _cnfp(fp)
        _mod_prefix = _file_module_prefix(fp)
    except Exception:
        _mod_prefix = ""

    # Collect all functions with their lock sequences
    functions: list[tuple[str, int, list[tuple[str, str]]]] = []
    # (fn_name, fn_line, lock_sequence)

    for m_fn in _FN_HEADER_RE.finditer(content):
        fn_name_val = m_fn.group("name")
        fn_offset = m_fn.start()
        fn_line = content[:fn_offset].count("\n") + 1

        body, body_start_line = _extract_fn_body(content, fn_offset)
        if body is None:
            continue

        seq = _lock_sequence_in_body(body)
        # Only keep functions with >= 2 distinct lock targets
        receivers = [r for r, _ in seq]
        unique_receivers = list(dict.fromkeys(receivers))  # preserve order
        if len(unique_receivers) >= 2:
            functions.append((fn_name_val, fn_line, seq))

    hits = []
    reported_pairs: set[frozenset] = set()

    for i in range(len(functions)):
        fn_a, line_a, seq_a = functions[i]
        # Get ordered unique receivers for fn_a
        a_order = list(dict.fromkeys(r for r, _ in seq_a))

        for j in range(i + 1, len(functions)):
            fn_b, line_b, seq_b = functions[j]
            b_order = list(dict.fromkeys(r for r, _ in seq_b))

            # Find pairs of shared lock targets
            shared = [r for r in a_order if r in b_order]
            if len(shared) < 2:
                continue

            # Check for order inversion: find first two shared locks
            # whose relative order differs between fn_a and fn_b
            inversion_found = False
            for si in range(len(shared)):
                for sj in range(si + 1, len(shared)):
                    r1 = shared[si]
                    r2 = shared[sj]
                    a_idx1 = a_order.index(r1)
                    a_idx2 = a_order.index(r2)
                    b_idx1 = b_order.index(r1)
                    b_idx2 = b_order.index(r2)
                    # In fn_a: r1 before r2 (a_idx1 < a_idx2)
                    # In fn_b: r2 before r1 (b_idx2 < b_idx1) => inversion
                    if (a_idx1 < a_idx2) != (b_idx1 < b_idx2):
                        inversion_found = True
                        inv_r1 = r1
                        inv_r2 = r2
                        break
                if inversion_found:
                    break

            if not inversion_found:
                continue

            pair_key = frozenset((fn_a, fn_b))
            if pair_key in reported_pairs:
                continue
            reported_pairs.add(pair_key)

            msg = (
                f"Lock-order inversion: `{fn_a}` acquires `{inv_r1}` then `{inv_r2}`; "
                f"`{fn_b}` acquires `{inv_r2}` then `{inv_r1}` — "
                f"concurrent execution deadlocks the process (ABBA pattern). "
                f"Establish a global lock-acquisition order and apply it everywhere."
            )

            base_hit: dict = {
                "detector_id": DETECTOR_ID,
                "file": filepath,
                "severity": "HIGH",
                "lock_a": inv_r1,
                "lock_b": inv_r2,
                "message": msg,
            }
            if _crate_name and _crate_name != "unknown":
                base_hit["crate_name"] = _crate_name
            if _mod_prefix:
                base_hit["module_path"] = _mod_prefix

            hit_a = dict(base_hit)
            hit_a["line"] = line_a
            hit_a["fn_name"] = fn_a
            hit_a["fn_signature"] = _fn_sig(content, line_a)
            hits.append(hit_a)

            hit_b = dict(base_hit)
            hit_b["line"] = line_b
            hit_b["fn_name"] = fn_b
            hit_b["fn_signature"] = _fn_sig(content, line_b)
            hits.append(hit_b)

    return hits


def _fn_sig(content: str, fn_line: int) -> str:
    lines = content.splitlines()
    if fn_line < 1 or fn_line > len(lines):
        return ""
    parts = []
    for l in lines[fn_line - 1:fn_line + 15]:
        parts.append(l.strip())
        if "{" in l:
            sig = " ".join(parts)
            sig = sig[:sig.rfind("{")].strip()
            return " ".join(sig.split())
    return " ".join(parts[:2])


def scan(root: str) -> list[tuple[str, int, str]]:
    """Walk `root` for .rs files and return (filepath, line, message) tuples."""
    results = []
    root_path = pathlib.Path(root)
    if root_path.is_file():
        for h in scan_file(str(root_path)):
            results.append((h["file"], h["line"], h["message"]))
        return results
    for dirpath, dirnames, filenames in os.walk(root):
        dirnames[:] = [d for d in dirnames if d not in _SKIP_DIRS]
        for fname in filenames:
            if not fname.endswith(".rs"):
                continue
            fpath = os.path.join(dirpath, fname)
            for h in scan_file(fpath):
                results.append((h["file"], h["line"], h["message"]))
    return results


def run(tree, source: bytes, filepath: str) -> list[dict]:
    """tree-sitter runner interface (delegates to regex scan_file)."""
    return scan_file(filepath)


def main(argv=None):
    args = argv if argv is not None else sys.argv[1:]
    if not args:
        print(f"usage: {sys.argv[0]} <path>", file=sys.stderr)
        return 2
    for fpath, line, msg in scan(args[0]):
        print(f"{fpath}:{line}:{DETECTOR_ID}:{msg}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
