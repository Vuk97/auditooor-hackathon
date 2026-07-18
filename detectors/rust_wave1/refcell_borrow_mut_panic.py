"""
refcell_borrow_mut_panic.py

Detects `RefCell::borrow_mut()` calls that may panic because a prior
`.borrow()` or `.borrow_mut()` guard is still live in the same scope.

`RefCell<T>` enforces borrow rules at runtime: calling `borrow_mut()` while
any outstanding `Ref<T>` or `RefMut<T>` exists on the same `RefCell` panics
immediately.  This is a common footgun when refactoring shared-state code from
single-threaded to more complex control flow.

Bug class: MEDIUM (panic — process crash, potential DoS).

Algorithm (pure regex, no tree-sitter dependency):
1. Extract all function bodies via brace-depth tracking.
2. Strip comments and string literals (so .borrow in comments is not matched).
3. Walk the cleaned body character by character, tracking:
   - Current brace depth.
   - Live borrow bindings: dict of receiver -> (offset, method, var, depth).
4. For each `.borrow_mut()` with a named binding:
   a. Check if any earlier binding for the same receiver is still in scope
      (i.e., its declaration depth <= current depth AND it has not been
      explicitly drop()-ped).
   b. If yes, flag the `borrow_mut()` call.
5. When brace depth decreases, evict bindings declared at the now-exited depth.

False-positive guards:
  - `try_borrow_mut()` — returns `Result<RefMut<T>, BorrowMutError>`; does NOT
    panic.  Not flagged.
  - `try_borrow()` — similarly returns `Result`; not flagged.
  - Explicit `drop(guard_var)` clears the binding.
  - Guard declared in a nested block (higher brace depth) is evicted when the
    block closes.
  - Bare `.borrow()` without a named binding — the temporary is dropped at the
    end of the statement; not tracked as a live binding.

Limitations:
  - Brace-depth eviction is conservative: a guard declared in an `if` arm may
    be evicted only when the `if` block closes, not when the arm exits.
  - Complex patterns like returning a `Ref<T>` from a function are not tracked.
"""
from __future__ import annotations

import os
import pathlib
import re
import sys
from typing import Optional

DETECTOR_ID = "rust_wave1.refcell_borrow_mut_panic"

_SKIP_DIRS = {"target", ".git", "node_modules", "vendor", "_archive"}

_FN_HEADER_RE = re.compile(
    r"^[ \t]*"
    r"(?:pub(?:\s*\([^)]*\))?\s+)?"
    r"(?:unsafe\s+|const\s+|async\s+)*"
    r"fn\s+(?P<name>[A-Za-z_]\w*)"
    r"(?:\s*<[^(>]*>)?\s*\(",
    re.MULTILINE,
)

# Binding: let [mut] var = <receiver>.borrow[_mut]()
_BORROW_BIND_RE = re.compile(
    r"let\s+(?:mut\s+)?(?P<var>[A-Za-z_]\w*)\s*=\s*"
    r"(?:[\w:.<>\*&\s]+?\.)*"
    r"(?P<receiver>[A-Za-z_]\w*)\s*\.\s*"
    r"(?P<method>borrow(?:_mut)?)\s*\(\s*\)",
)

# try_borrow / try_borrow_mut — safe (returns Result)
_TRY_BORROW_RE = re.compile(
    r"\.\s*try_borrow(?:_mut)?\s*\(\s*\)"
)

# drop() call
_DROP_RE = re.compile(r"\bdrop\s*\(\s*(?P<var>[A-Za-z_]\w*)\s*\)")

_LINE_COMMENT_RE = re.compile(r"//[^\n]*")
_BLOCK_COMMENT_RE = re.compile(r"/\*.*?\*/", re.DOTALL)
_STRING_LITERAL_RE = re.compile(r'"(?:[^"\\]|\\.)*"')


def _strip_comments_and_strings(text: str) -> str:
    """Remove comments and string literals, preserving line count."""
    def _blank_nl(m: "re.Match[str]") -> str:
        s = m.group(0)
        return "\n".join(" " * len(part) for part in s.split("\n"))

    text = _STRING_LITERAL_RE.sub(lambda m: " " * len(m.group(0)), text)
    text = _LINE_COMMENT_RE.sub(lambda m: " " * len(m.group(0)), text)
    text = _BLOCK_COMMENT_RE.sub(_blank_nl, text)
    return text


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


def _line_in_body(body: str, offset: int, body_start_line: int) -> int:
    return body_start_line + body[:offset].count("\n")


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


def _find_borrow_conflicts(body_clean: str) -> list[tuple[int, int, str, str, str]]:
    """Return list of (borrow_offset, borrow_mut_offset, receiver, prev_method, var).

    Uses a scope-aware walk: tracks brace depth so that bindings declared in
    an inner block are evicted when the block closes (depth decreases).
    """
    n = len(body_clean)

    # Collect all borrow binding events and drop events, ordered by offset
    # Each event: (offset, kind, ...)
    events: list[tuple[int, str, str, str, str]] = []
    # kind = "bind", receiver, method, var
    # kind = "drop", "", "", var

    # Skip try_borrow offsets
    try_offsets = {m.start() for m in _TRY_BORROW_RE.finditer(body_clean)}

    for m in _BORROW_BIND_RE.finditer(body_clean):
        # Skip if overlaps with a try_borrow
        if any(abs(m.start() - t) < 30 for t in try_offsets):
            continue
        events.append((m.start(), "bind", m.group("receiver"), m.group("method"), m.group("var")))

    for m in _DROP_RE.finditer(body_clean):
        events.append((m.start(), "drop", "", "", m.group("var")))

    events.sort(key=lambda x: x[0])

    # Walk body_clean character by character to track brace depth and process events
    # We process events in order, evicting bindings when depth decreases

    conflicts: list[tuple[int, int, str, str, str]] = []

    # live_borrows: receiver -> (offset, method, var, decl_depth)
    live_borrows: dict[str, tuple[int, str, str, int]] = {}

    # Track brace depth at each event offset
    def _depth_at(offset: int) -> int:
        d = 0
        for ch in body_clean[:offset]:
            if ch == "{":
                d += 1
            elif ch == "}":
                d -= 1
        return d

    prev_depth = 0
    ei = 0
    i = 0
    event_idx = 0

    # Process events in offset order, computing depth at each event
    for ev_offset, ev_kind, ev_recv, ev_method, ev_var in events:
        # Compute depth at this event
        current_depth = _depth_at(ev_offset)

        # Evict bindings from deeper scopes that have now been closed
        # (i.e., declared at depth > current_depth are out of scope)
        to_evict = [r for r, (_, _, _, d) in live_borrows.items() if d >= current_depth + 1]
        # Actually we want to evict those declared at depth GREATER than current_depth
        # But we only know depth decreased at the close brace; since we process events
        # in order and compute depth, we evict at each event where depth might have dropped
        to_evict = [r for r, (_, _, _, d) in live_borrows.items() if d > current_depth]
        for r in to_evict:
            del live_borrows[r]

        if ev_kind == "drop":
            # Evict binding with this var name
            to_remove = [r for r, (_, _, v, _) in live_borrows.items() if v == ev_var]
            for r in to_remove:
                del live_borrows[r]

        elif ev_kind == "bind":
            if ev_method == "borrow_mut":
                # Check if same receiver has a live borrow
                if ev_recv in live_borrows:
                    prev_offset, prev_method, prev_var, prev_d = live_borrows[ev_recv]
                    conflicts.append((prev_offset, ev_offset, ev_recv, prev_method, prev_var))
                # Update live_borrows with this borrow_mut (it's now the live guard)
                live_borrows[ev_recv] = (ev_offset, ev_method, ev_var, current_depth)
            else:
                # borrow() — track as live binding
                live_borrows[ev_recv] = (ev_offset, ev_method, ev_var, current_depth)

    return conflicts


def scan_file(filepath: str) -> list[dict]:
    try:
        with open(filepath, encoding="utf-8", errors="replace") as fh:
            content = fh.read()
    except OSError:
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

        body, body_start_line = _extract_fn_body(content, fn_offset)
        if body is None:
            continue

        body_clean = _strip_comments_and_strings(body)
        conflicts = _find_borrow_conflicts(body_clean)

        for prev_offset, bm_offset, receiver, prev_method, prev_var in conflicts:
            borrow_line = _line_in_body(body_clean, prev_offset, body_start_line)
            borrow_mut_line = _line_in_body(body_clean, bm_offset, body_start_line)

            hit: dict = {
                "detector_id": DETECTOR_ID,
                "file": filepath,
                "line": borrow_mut_line,
                "fn_name": fn_name_val,
                "borrow_line": borrow_line,
                "borrow_mut_line": borrow_mut_line,
                "receiver": receiver,
                "severity": "MEDIUM",
                "message": (
                    f"fn `{fn_name_val}`: `{receiver}.borrow_mut()` at line "
                    f"{borrow_mut_line} called while `{receiver}.{prev_method}()` "
                    f"guard (line {borrow_line}) is still live — "
                    f"panics at runtime. Drop the earlier borrow before calling "
                    f"`borrow_mut()`, or use `try_borrow_mut()` to handle gracefully."
                ),
            }
            if _crate_name and _crate_name != "unknown":
                hit["crate_name"] = _crate_name
            if _mod_prefix:
                hit["module_path"] = _mod_prefix
            sig = _fn_sig(content, fn_line)
            if sig:
                hit["fn_signature"] = sig
            hits.append(hit)

    return hits


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
