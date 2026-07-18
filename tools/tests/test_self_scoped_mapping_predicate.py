#!/usr/bin/env python3
"""PR #121 B5 — unit tests for `function.is_self_scoped_mapping_write`.

The predicate is a NEGATIVE PRECONDITION carve-out for
unauthenticated-state-write detectors: it returns True for the
"self-action" shape where every mapping write in the function body is
indexed by `msg.sender` (e.g. POLY UserPausable's `pauseUser()` /
`unpauseUser()` — a user mutating only their own slot is intentional,
not an auth bug). Detectors that want to suppress this shape add:

    match:
      - function.is_self_scoped_mapping_write: false

These tests pin the predicate's contract so future changes don't
silently widen or narrow the carve-out.

Slither isn't required: the predicate only consumes
`function.source_mapping.content` (same as `body_contains_regex`).
We feed it a minimal MockFunction with the body string.
"""
from __future__ import annotations

import sys
import unittest
from pathlib import Path

# Make the repo root importable for `detectors._predicate_engine`.
ROOT = Path(__file__).resolve().parents[2]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from detectors._predicate_engine import _check_function_pred  # noqa: E402


class _MockSourceMapping:
    def __init__(self, content: str) -> None:
        self.content = content


class MockFunction:
    """Minimal stand-in for a Slither Function object.

    The predicate only reads `.source_mapping.content`, so we don't need
    nodes/IR/etc. Other attributes are populated as no-ops to be safe.
    """

    def __init__(self, body: str, name: str = "f") -> None:
        # Wrap with a function-shaped header + braces — the predicate
        # locates the body by scanning from the first `{`.
        wrapped = f"function {name}() public {{\n{body}\n}}"
        self.source_mapping = _MockSourceMapping(wrapped)
        self.name = name
        self.parameters = []
        self.modifiers = []
        self.nodes = []


def _eval(body: str) -> bool:
    fn = MockFunction(body)
    return _check_function_pred(fn, "function.is_self_scoped_mapping_write", True)


class SelfScopedMappingWritePredicateTests(unittest.TestCase):
    # ── Positive cases ────────────────────────────────────────────────

    def test_simple_msg_sender_assign_is_self_scoped(self) -> None:
        """Canonical POLY UserPausable shape — single `[msg.sender] = true`."""
        self.assertTrue(_eval("isPaused[msg.sender] = true;"))

    def test_delete_msg_sender_is_self_scoped(self) -> None:
        """`delete x[msg.sender]` is a self-scoped clear."""
        self.assertTrue(_eval("delete isPaused[msg.sender];"))

    def test_struct_field_write_via_msg_sender_is_self_scoped(self) -> None:
        """`x[msg.sender].field = ...` still indexes by msg.sender."""
        self.assertTrue(_eval("userInfo[msg.sender].active = true;"))

    def test_compound_assign_msg_sender_is_self_scoped(self) -> None:
        """`+=` on msg.sender slot is a self-scoped write."""
        self.assertTrue(_eval("balances[msg.sender] += 1;"))

    def test_multiple_msg_sender_writes_all_self_scoped(self) -> None:
        """Two writes both keyed on msg.sender — still True."""
        body = (
            "isPaused[msg.sender] = true;\n"
            "lastPausedAt[msg.sender] = block.timestamp;\n"
        )
        # block.timestamp is a read, not a write — but `lastPausedAt[msg.sender]`
        # IS a mapping write. Both writes are self-scoped → True.
        self.assertTrue(_eval(body))

    def test_msg_sender_with_whitespace_is_self_scoped(self) -> None:
        """Tolerate `msg . sender` (Solidity allows whitespace)."""
        self.assertTrue(_eval("isPaused[ msg . sender ] = true;"))

    # ── Negative cases ────────────────────────────────────────────────

    def test_arbitrary_user_param_is_not_self_scoped(self) -> None:
        """Writing to another user's slot fails the predicate."""
        self.assertFalse(_eval("isPaused[u] = true;"))

    def test_address_literal_is_not_self_scoped(self) -> None:
        """An explicit address (not msg.sender) fails."""
        self.assertFalse(_eval("isPaused[0x0000000000000000000000000000000000000001] = true;"))

    def test_mixed_msg_sender_and_other_user_is_not_self_scoped(self) -> None:
        """One self-write + one other-user write → fails."""
        body = (
            "isPaused[msg.sender] = true;\n"
            "isPaused[other] = true;\n"
        )
        self.assertFalse(_eval(body))

    def test_mixed_msg_sender_and_scalar_is_not_self_scoped(self) -> None:
        """Self-mapping write + scalar state write → fails (Codex case)."""
        body = (
            "isPaused[msg.sender] = true;\n"
            "counter += 1;\n"
        )
        self.assertFalse(_eval(body))

    def test_empty_function_is_not_self_scoped(self) -> None:
        """Zero writes → fails (predicate requires >= 1 self-write)."""
        self.assertFalse(_eval(""))

    def test_only_reads_is_not_self_scoped(self) -> None:
        """Read-only function → fails (no writes at all)."""
        body = "uint256 x = isPaused[msg.sender] ? 1 : 0;"
        self.assertFalse(_eval(body))

    def test_comment_with_msg_sender_does_not_count(self) -> None:
        """Comments are stripped — `// x[msg.sender] = 1;` is not a write."""
        body = "// isPaused[msg.sender] = true;\nisPaused[u] = true;"
        self.assertFalse(_eval(body))

    def test_string_literal_with_msg_sender_does_not_count(self) -> None:
        """String literals are stripped — `\"x[msg.sender]=\"` is not a write."""
        body = 'string memory note = "x[msg.sender]=fake"; isPaused[u] = true;'
        self.assertFalse(_eval(body))

    def test_local_var_decl_does_not_count_as_scalar_write(self) -> None:
        """`uint256 x = ...;` is a stack decl, not a state write — should pass."""
        body = (
            "uint256 nowTs = block.timestamp;\n"
            "isPaused[msg.sender] = true;\n"
        )
        self.assertTrue(_eval(body))

    # ── Codex blocker: scalar ++/-- mutations ─────────────────────────
    # The original scalar-write heuristic only caught `=` / `+=` / `-=`
    # forms — a mixed `counter++` snuck through and the predicate
    # incorrectly returned True. These pin the fix.

    def test_self_scoped_with_scalar_post_increment_rejected(self) -> None:
        """`isPaused[msg.sender] = true; counter++;` → False (mixed scalar write)."""
        body = (
            "isPaused[msg.sender] = true;\n"
            "counter++;\n"
        )
        self.assertFalse(_eval(body))

    def test_self_scoped_with_scalar_pre_decrement_rejected(self) -> None:
        """`isPaused[msg.sender] = true; --counter;` → False (mixed scalar write)."""
        body = (
            "isPaused[msg.sender] = true;\n"
            "--counter;\n"
        )
        self.assertFalse(_eval(body))

    def test_self_scoped_with_scalar_post_decrement_rejected(self) -> None:
        """`isPaused[msg.sender] = true; counter--;` → False (mixed scalar write)."""
        body = (
            "isPaused[msg.sender] = true;\n"
            "counter--;\n"
        )
        self.assertFalse(_eval(body))


if __name__ == "__main__":
    unittest.main()
