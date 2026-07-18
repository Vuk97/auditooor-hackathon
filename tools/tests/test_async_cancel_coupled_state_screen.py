"""Focused fixtures for the typed async lifecycle obligation substrate."""
from __future__ import annotations

import importlib.util
import unittest
from pathlib import Path

HERE = Path(__file__).resolve().parent
SCRIPT = HERE.parent / "async-cancel-coupled-state-screen.py"
SPEC = importlib.util.spec_from_file_location("async_cancel_screen", SCRIPT)
assert SPEC and SPEC.loader
MOD = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(MOD)  # type: ignore[union-attr]


def scan(source: str):
    return MOD.scan_file(Path("fixture.rs"), "fixture.rs", source)


VULNERABLE = """
pub struct Worker { state_a: bool, state_b: bool }
impl Worker {
    pub async fn process(&mut self) {
        self.state_a = true;
        retry_with_backoff().await;
        self.state_b = true;
        timeout_cleanup_backlog().await;
    }
}
"""

CLEAN = """
pub struct Worker { state_a: bool, state_b: bool }
impl Worker {
    pub async fn process(&mut self) {
        self.state_a = true;
        let _guard = scopeguard::guard((), |_| { self.state_a = false; });
        timeout_cleanup_backlog().await;
        self.state_b = true;
        rollback_if_retry_fails().await;
    }
}
"""

MUTATION = """
pub struct Worker { state_a: bool, state_b: bool }
impl Worker {
    pub async fn process(&mut self) {
        self.state_a = true;
        select! { _ = wait_for_event().await => {} }
        self.state_b = true;
    }
}
// retry timeout cleanup backlog must not become evidence when it is only a comment.
"""


class TestAsyncCancelCoupledStateScreen(unittest.TestCase):
    def test_vulnerable_emits_typed_lifecycle_obligation(self):
        rows = scan(VULNERABLE)
        self.assertEqual(len(rows), 1)
        row = rows[0]
        self.assertEqual(row["schema"], MOD.HYP_SCHEMA)
        self.assertEqual(row["obligation_type"], "typed_async_lifecycle_transition")
        self.assertEqual({m["kind"] for m in row["lifecycle_markers"]}, {"cancellation", "retry", "timeout", "cleanup", "backlog"})
        for field in ("source_refs", "preconditions", "suspected_violation", "expected_invariant", "proof_task_kind", "terminal_condition", "kill_condition"):
            self.assertIn(field, row)
        self.assertTrue(row["fires"])

    def test_clean_retains_obligation_but_is_unwound(self):
        rows = scan(CLEAN)
        self.assertEqual(len(rows), 1)
        self.assertTrue(rows[0]["has_unwind"])
        self.assertEqual(rows[0]["unwind_kind"], "scopeguard")
        self.assertFalse(rows[0]["fires"])
        self.assertIn("timeout", {m["kind"] for m in rows[0]["lifecycle_markers"]})

    def test_mutation_fixture_ignores_comment_markers(self):
        rows = scan(MUTATION)
        self.assertEqual(len(rows), 1)
        self.assertEqual({m["kind"] for m in rows[0]["lifecycle_markers"]}, {"cancellation"})
        self.assertTrue(rows[0]["fires"])


if __name__ == "__main__":
    unittest.main()
