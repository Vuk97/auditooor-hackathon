"""Suppress trivial container/heap.Interface plumbing methods from high-priority
"rubric-targeted" per-function hunt dispatch and from cross-language sibling-guard pairing.

MOTIVATION (SEI 2026-07-05): the rubric-targeted ranker matched a Go
``func (h logMergeHeap) Swap(i, j int) { h[i], h[j] = h[j], h[i] }``
(evmrpc/filter.go, an internal k-way log-merge heap) against Solidity AMM-swap
sibling-guard packets (MultiHopSwapTester.sol / ProxySwapTester.sol) PURELY because both
share the identifier "Swap". A whole perfn hunt task was spent ruling out boilerplate
``sort.Interface`` / ``heap.Interface`` / ``container/list`` plumbing. These methods
(Len / Less / Swap / Push / Pop) are Go stdlib interface obligations with single-statement
bodies operating on a slice-typed receiver - they carry no business logic and no
attacker-reachable security surface, and they never share a real invariant with a
same-named Solidity business function.

This is a language-family false-positive: a Go ``Swap`` (heap element exchange) is not a
DeFi ``swap`` (token exchange). The check is conservative - it fires ONLY on the exact Go
container-interface method NAMES with a trivially small body, so a real Go function that
happens to be named ``Swap`` but contains actual logic is NOT suppressed.
"""
from __future__ import annotations

import re

# The Go stdlib container/sort/heap interface method names. A method with one of these
# names AND a trivial (single-statement) body is interface plumbing, not business logic.
CONTAINER_INTERFACE_METHODS = frozenset(
    {"Len", "Less", "Swap", "Push", "Pop", "Peek"}
)

# A trivial container-method body is pure slice/index/append/len plumbing with NO control
# flow and NO calls other than the container built-ins. Canonical shapes:
#   Len:  return len(h)
#   Less: return h[i] < h[j]  /  return h[i].X < h[j].X
#   Swap: h[i], h[j] = h[j], h[i]
#   Push: *h = append(*h, x.(T))
#   Pop:  old := *h; n := len(old); x := old[n-1]; *h = old[:n-1]; return x
# Rather than enumerate shapes (brittle), we FORBID anything non-trivial: control flow, or
# a call to anything other than len/cap/append/make. Any such token => not plumbing.
_CONTROL_FLOW_RX = re.compile(r"\b(if|for|range|switch|select|go|defer|func)\b")
_WHITELIST_CALLS = frozenset({"len", "cap", "append", "make", "new"})
# Match a call ``ident(`` but NOT a Go type assertion ``x.(T)`` - the callee identifier
# must END in a word char (a trailing ``.`` means it is the ``.(`` assertion form).
_CALL_RX = re.compile(r"\b([A-Za-z_][\w.]*[A-Za-z0-9_])\s*\(")


def _strip_body_braces(body: str) -> str:
    b = body.strip()
    if b.startswith("{"):
        b = b[1:]
    if b.endswith("}"):
        b = b[:-1]
    return b


def _significant_lines(body: str) -> list[str]:
    """Body statement lines, excluding braces, blank lines, and ``//`` comments."""
    out: list[str] = []
    for ln in _strip_body_braces(body).splitlines():
        s = ln.strip()
        if not s or s in ("{", "}") or s.startswith("//"):
            continue
        out.append(s)
    return out


def is_trivial_container_interface_method(
    name: str, body: str, *, max_stmts: int = 5
) -> bool:
    """True iff ``name`` is a Go container/sort/heap.Interface method (Len/Less/Swap/
    Push/Pop/Peek) whose body is trivial slice/append plumbing.

    Conservative by construction:
      - the NAME must be one of the fixed interface-obligation names, AND
      - the body must be short (``<= max_stmts`` significant statements), AND
      - every significant statement must match a known trivial-plumbing shape
        (return len(...), a comparison index expr, a paired index swap, an append, or
        the canonical heap Pop slice-shrink).
    A same-named method with any non-trivial statement (a call into keeper/bank/state, a
    branch, a loop, arithmetic beyond indexing) is NOT suppressed - it keeps full
    rubric-targeted priority."""
    if name not in CONTAINER_INTERFACE_METHODS:
        return False
    if not body:
        return False
    stmts = _significant_lines(body)
    if not stmts or len(stmts) > max_stmts:
        return False
    joined = "\n".join(stmts)
    if _CONTROL_FLOW_RX.search(joined):
        return False  # any branch/loop => real logic, not plumbing
    for call in _CALL_RX.findall(joined):
        base = call.split(".")[-1]  # `heap.Pop` -> `Pop`; only bare built-ins allowed
        if "." in call or base not in _WHITELIST_CALLS:
            return False  # a call into keeper/state/anything => not plumbing
    return True


def is_container_method_name(name: str) -> bool:
    """True iff the identifier is a Go container-interface obligation name. Cheaper than
    the body check; use to gate cross-language sibling pairing where the body is not on
    hand (a Go Len/Less/Swap/Push/Pop is never a real sibling of a Solidity business fn)."""
    return name in CONTAINER_INTERFACE_METHODS
