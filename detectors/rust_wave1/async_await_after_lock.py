"""
async_await_after_lock.py

Flags `async fn` bodies that hold a Mutex/RwLock guard across an `.await`
point.  This is the canonical tokio async deadlock: `tokio::sync::Mutex` (and
`parking_lot::Mutex`, `std::sync::Mutex`) block the async executor thread when
awaited while the guard is live, deadlocking the runtime.

Bug class: HIGH (DoS) — the async executor thread (or the whole single-
threaded runtime) stalls permanently.  Empirical anchor: dYdX cantina-202
CRITICAL (iavl-1024 Go RWMutex/channel held across goroutine await analogue).

Algorithm (pure regex, no tree-sitter dependency):
1. Find each `async fn` body via brace-depth tracking.
2. Within the body, find every `.lock()` / `.read()` / `.write()` call that
   assigns its result to a named variable binding (the guard is live).
   - `.lock().await` is the SAFE pattern (the await IS on the lock call);
     we record the END position after `.await` so that only subsequent
     `.await` expressions (past the lock+await) are candidates.
   - `.lock()` without an immediate `.await` (std::sync::Mutex) holds the
     guard synchronously; any `.await` after it is a deadlock.
3. If `.await` appears AFTER the first guard-binding position AND before an
   explicit `drop(guard_var)` of the guard variable, flag the function.

False-positive guards applied:
  - `lock().await` — the `.await` that acquires the async lock is not itself
    a deadlock; we move the search window to after that `.await`.
  - `drop(guard_var)` between the lock and the subsequent `.await` clears the
    flag.
  - `lock_owned()` — produces a `Send` guard; excluded.
  - Guard inside inner brace scope (heuristic: guard variable declared in a
    block `{ let guard = .lock(); ... }` — the scope end `}` drops the guard;
    detected via brace-depth tracking in the body).
  - Type-guard gating (FP precision): a `spin::` receiver is a busy-spin
    (non-yielding) lock and is skipped. `read()/write()/try_read()/try_write()`
    are ambiguous (io traits, sockets, channels, serde readers all expose
    these) and are skipped UNLESS a blocking-lock type is positively in
    evidence in the file (a `use tokio::sync` / `use std::sync` / `use
    parking_lot` import, or a `: RwLock<` / `Arc<RwLock<` / `: Mutex<` type
    annotation). When the lock type is NOT positively resolved to a blocking
    guard, severity is downgraded HIGH -> MEDIUM.

Limitations (regex approach):
  - Approximate scope analysis; may miss cases where the guard is stored in a
    struct field and awaited later.
  - `try_lock()` / `try_read()` return `Option`/`Result` — the guard is only
    live if the `Some`/`Ok` arm executes; flagged conservatively.
"""
from __future__ import annotations

import os
import pathlib
import re
import sys
from typing import Optional

DETECTOR_ID = "rust_wave1.async_await_after_lock"

_SKIP_DIRS = {"target", ".git", "node_modules", "vendor", "_archive"}

_ASYNC_FN_RE = re.compile(
    r"^[ \t]*"
    r"(?:pub(?:\s*\([^)]*\))?\s+)?"
    r"(?:unsafe\s+)?"
    r"async\s+fn\s+(?P<name>[A-Za-z_]\w*)"
    r"(?:\s*<[^(>]*>)?\s*\(",
    re.MULTILINE,
)

# Pattern: `let [mut] var = <chain>.lock()` optionally followed by `.await`
# Group `await_suffix` captures the `.await` if present (safe async lock pattern)
_LOCK_ASSIGN_RE = re.compile(
    r"let\s+(?:mut\s+)?(?P<var>[A-Za-z_]\w*)\s*=\s*"
    r"[\w:.<>\*&\s]+?"
    r"\.(?P<method>lock|read|write|try_lock|try_read|try_write)\s*\(\s*\)"
    r"(?P<await_suffix>\s*\.\s*await)?",
)

# lock_owned() — the guard is Send, not a deadlock
_LOCK_OWNED_RE = re.compile(r"\.\s*lock_owned\s*\(\s*\)")

# Blocking-lock-type evidence in the file: an import of a synchronization
# primitive crate, or an explicit type annotation that names a blocking
# RwLock / Mutex.  Used to positively resolve a `.read()/.write()` (or any
# lock) receiver to a blocking guard type before flagging.  Without one of
# these the `.read()/.write()` is just as likely an io::Read/Write, a
# serde reader, a `.read()` on a channel/socket, etc. — not a lock guard.
_BLOCKING_LOCK_IMPORT_RE = re.compile(
    r"use\s+tokio::sync\b"
    r"|use\s+std::sync\b"
    r"|use\s+parking_lot\b"
    r"|:\s*RwLock\s*<"
    r"|Arc\s*<\s*RwLock\s*<"
    r"|:\s*Mutex\s*<"
)

# spin::Mutex / spin::RwLock — a busy-spin lock, non-yielding: holding it
# across .await does NOT park the async executor in the deadlock sense the
# detector targets, so a spin:: receiver is not flaggable here.
# Matched against (a) the per-candidate assignment fragment (covers
# fully-qualified `spin::Mutex::lock(...)`) and (b) the whole file when spin
# is the only lock crate in evidence (covers typed fields like
# `Arc<spin::Mutex<T>>` whose receiver fragment is just `self.state`).
_SPIN_LOCK_RE = re.compile(r"\bspin\s*::")

# A blocking-AND-yielding lock crate import (tokio::sync / std::sync /
# parking_lot). If the file imports a spin lock but NONE of these, the locks
# in play are spin (non-yielding) and the await-after-lock shape is not the
# targeted runtime deadlock.
_YIELDING_LOCK_IMPORT_RE = re.compile(
    r"use\s+tokio::sync\b"
    r"|use\s+std::sync::(?:Mutex|RwLock)\b"
    r"|use\s+std::sync::\{[^}]*(?:Mutex|RwLock)"
    r"|use\s+parking_lot\b"
)
_SPIN_IMPORT_RE = re.compile(r"use\s+spin\b")

# read/write/try_read/try_write are ambiguous (io traits, channels, sockets,
# serde, etc.); only treat them as lock guards when a blocking-lock type is
# positively in evidence in the file.
_RWLOCK_METHODS = {"read", "write", "try_read", "try_write"}

# Any standalone .await (not preceded immediately by lock())
_AWAIT_RE = re.compile(r"\.await\b")

# drop() call
_DROP_RE = re.compile(r"\bdrop\s*\(\s*(?P<var>[A-Za-z_]\w*)\s*\)")

_LINE_COMMENT_RE = re.compile(r"//[^\n]*")
_BLOCK_COMMENT_RE = re.compile(r"/\*.*?\*/", re.DOTALL)
_STRING_LITERAL_RE = re.compile(r'"(?:[^"\\]|\\.)*"')


def _strip_comments_and_strings(text: str) -> str:
    """Remove line comments, block comments, and string literals from text.

    Preserves line count (newlines are kept) so that line-number arithmetic
    remains correct.  String literals replaced with spaces so .await inside
    a string like "no further .await" does not produce a false positive.
    """
    # Replace string literals first (before stripping comments that may be
    # inside strings)
    def _blank_preserve_newlines(m: "re.Match[str]") -> str:
        s = m.group(0)
        return "\n".join(" " * len(part) for part in s.split("\n"))

    text = _STRING_LITERAL_RE.sub(lambda m: " " * len(m.group(0)), text)
    # Line comments: blank everything after //
    text = _LINE_COMMENT_RE.sub(lambda m: " " * len(m.group(0)), text)
    # Block comments: blank, preserving newlines
    text = _BLOCK_COMMENT_RE.sub(_blank_preserve_newlines, text)
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


def _brace_depth_at(body: str, offset: int) -> int:
    """Return brace nesting depth at `offset` within `body`."""
    depth = 0
    for ch in body[:offset]:
        if ch == "{":
            depth += 1
        elif ch == "}":
            depth -= 1
    return depth


def _line_in_body(body: str, offset: int, body_start_line: int) -> int:
    return body_start_line + body[:offset].count("\n")


def _fn_sig(content: str, fn_line: int) -> str:
    lines = content.splitlines()
    if fn_line < 1 or fn_line > len(lines):
        return ""
    parts = []
    for l in lines[fn_line - 1:fn_line + 20]:
        parts.append(l.strip())
        if "{" in l:
            sig = " ".join(parts)
            sig = sig[:sig.rfind("{")].strip()
            return " ".join(sig.split())
    return " ".join(parts[:3])


def scan_file(filepath: str) -> list[dict]:
    try:
        with open(filepath, encoding="utf-8", errors="replace") as fh:
            content = fh.read()
    except OSError:
        return []

    fp = pathlib.Path(filepath)

    # File-level evidence that a blocking lock type is in play. Computed once.
    file_has_blocking_lock_type = bool(_BLOCKING_LOCK_IMPORT_RE.search(content))

    # spin-only file: imports a spin lock but NO yielding lock crate. Every
    # lock here is a busy-spin (non-yielding) lock, so the await-after-lock
    # shape is not the targeted tokio-runtime deadlock. (Covers typed fields
    # like `Arc<spin::Mutex<T>>` whose receiver fragment is just `self.state`.)
    file_is_spin_only = bool(_SPIN_IMPORT_RE.search(content)) and not bool(
        _YIELDING_LOCK_IMPORT_RE.search(content)
    )

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

    for m_fn in _ASYNC_FN_RE.finditer(content):
        fn_name_val = m_fn.group("name")
        fn_offset = m_fn.start()

        body, body_start_line = _extract_fn_body(content, fn_offset)
        if body is None:
            continue

        # Strip comments and string literals so we don't match .await in comments
        body_clean = _strip_comments_and_strings(body)

        # Find lock assignments in the body
        # For each, determine:
        #   - search_start: position after which we look for a problematic .await
        #     * if `lock().await` pattern: search_start = end of the `.await` suffix
        #       (the lock acquisition itself is safe; look for .await AFTER it)
        #     * if `lock()` without .await: search_start = end of match
        #       (any .await after is a deadlock)
        #   - guard_var: the variable that holds the guard
        #   - guard_scope_depth: brace depth at the declaration site
        #   - lock_line / lock_method

        candidate_locks: list[dict] = []

        for m_lock in _LOCK_ASSIGN_RE.finditer(body_clean):
            fragment = body_clean[m_lock.start():m_lock.end()]
            if _LOCK_OWNED_RE.search(fragment):
                continue

            var = m_lock.group("var")
            method = m_lock.group("method")
            await_suffix = m_lock.group("await_suffix")

            # --- Type-guard gating (FP precision) --------------------------
            # spin::Mutex / spin::RwLock receivers busy-spin instead of
            # yielding to the executor; holding one across .await is not the
            # tokio-runtime deadlock this detector targets. Skip when the
            # fragment is fully-qualified spin:: OR the file is spin-only.
            if _SPIN_LOCK_RE.search(fragment) or file_is_spin_only:
                continue

            # read/write/try_read/try_write are ambiguous: io::Read/Write,
            # sockets, channels, serde readers, etc. all expose these names.
            # Only treat them as lock guards when a blocking-lock type is
            # positively in evidence somewhere in the file.
            if method in _RWLOCK_METHODS and not file_has_blocking_lock_type:
                continue

            # Positive type resolution: a `.lock()` receiver with a blocking
            # import / annotation in the file, OR a `.read()/.write()` that
            # survived the gate above (which requires the blocking-type
            # evidence). Used to set severity (HIGH if resolved, else MEDIUM).
            type_resolved_blocking = (
                file_has_blocking_lock_type
                or (method in {"lock", "try_lock"} and bool(await_suffix))
            )

            # Position where the guard is live (after the full assignment)
            lock_end = m_lock.end()

            # The brace depth at the guard declaration
            guard_depth = _brace_depth_at(body_clean, m_lock.start())

            candidate_locks.append({
                "var": var,
                "method": method,
                "has_await_suffix": bool(await_suffix),
                "lock_end": lock_end,  # search for problematic .await after this
                "lock_offset": m_lock.start(),
                "guard_depth": guard_depth,
                "type_resolved_blocking": type_resolved_blocking,
            })

        if not candidate_locks:
            continue

        # For each candidate lock, find a subsequent .await that is:
        # 1. After lock_end in the body
        # 2. At the same or inner brace depth as the guard declaration
        # 3. Not preceded by a drop(guard_var)
        for lock_info in candidate_locks:
            var = lock_info["var"]
            lock_end = lock_info["lock_end"]
            method = lock_info["method"]
            guard_depth = lock_info["guard_depth"]
            type_resolved_blocking = lock_info["type_resolved_blocking"]

            # Collect drop positions for this guard var
            drop_positions = set()
            for m_drop in _DROP_RE.finditer(body_clean):
                if m_drop.group("var") == var and m_drop.start() > lock_end:
                    drop_positions.add(m_drop.start())

            # Find the first .await after lock_end that is not part of the
            # lock call itself, and where the guard is still in scope
            found_await = None
            for m_aw in _AWAIT_RE.finditer(body_clean):
                aw_start = m_aw.start()
                if aw_start <= lock_end:
                    continue

                # Check depth: if we've exited the guard's scope, it's dropped
                current_depth = _brace_depth_at(body_clean, aw_start)
                if current_depth < guard_depth:
                    # We've exited the scope where the guard was declared — dropped
                    break

                # Check if a drop() happened before this await
                dropped = any(dp < aw_start for dp in drop_positions)
                if dropped:
                    break

                found_await = m_aw
                break

            if found_await is None:
                continue

            lock_line = _line_in_body(body, lock_info["lock_offset"], body_start_line)
            await_line = _line_in_body(body, found_await.start(), body_start_line)
            fn_line = content[:fn_offset].count("\n") + 1

            # Severity: HIGH only when the lock type is positively resolved to
            # a blocking guard; otherwise downgrade to MEDIUM (the await-after-
            # lock shape is suggestive but the receiver type is unconfirmed).
            severity = "HIGH" if type_resolved_blocking else "MEDIUM"

            hit: dict = {
                "detector_id": DETECTOR_ID,
                "file": filepath,
                "line": fn_line,
                "fn_name": fn_name_val,
                "lock_line": lock_line,
                "await_line": await_line,
                "lock_method": method,
                "severity": severity,
                "type_resolved_blocking": type_resolved_blocking,
                "message": (
                    f"async fn `{fn_name_val}`: `.{method}()` guard `{var}` held "
                    f"across `.await` (lock line {lock_line}, await line {await_line}) "
                    f"— deadlock risk. Drop the guard before awaiting or restructure "
                    f"so the guard does not span an await point."
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
            break  # one hit per function is sufficient

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
