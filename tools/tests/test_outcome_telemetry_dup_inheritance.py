#!/usr/bin/env python3
"""Regression test for the duplicate-inheritance rule (iter13 triager learning).

Playbook §5 says: when a duplicate row carries its parent's known outcome in
the status string (e.g. "Rejected (duplicate of rejected original)"), the row
MUST normalize to the inherited outcome — NOT to `duplicate`. The `duplicate`
bucket is reserved for rows where the parent outcome is genuinely unknown.

Pre-fix: `normalize_outcome()` checked "duplicate" before "rejected", so any
status containing both words collapsed to `duplicate`. Post-fix: precedence is
paid/accepted → rejected → in_review → duplicate-only → pending → unknown.
"""
from __future__ import annotations

import importlib.util
import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
TOOLS_DIR = ROOT / "tools"
TOOL = TOOLS_DIR / "outcome-telemetry.py"

# outcome-telemetry.py imports sibling module `submission_ledger`; add the
# tools dir to sys.path so the sibling resolves at spec_from_file_location
# time. Without this the import fails even though the file exists.
if str(TOOLS_DIR) not in sys.path:
    sys.path.insert(0, str(TOOLS_DIR))


def _load_module():
    spec = importlib.util.spec_from_file_location("outcome_telemetry", TOOL)
    mod = importlib.util.module_from_spec(spec)
    assert spec.loader is not None
    # Python 3.14 dataclass-decorator inspects sys.modules[cls.__module__]
    # during class construction; register the module BEFORE exec_module so
    # @dataclass on OutcomeRecord doesn't hit AttributeError on None.__dict__.
    sys.modules[spec.name] = mod
    spec.loader.exec_module(mod)
    return mod


class DupInheritanceTest(unittest.TestCase):
    def setUp(self) -> None:
        self.mod = _load_module()

    # --- dup-of-rejected → rejected ------------------------------------
    def test_duplicate_of_rejected_normalizes_to_rejected(self) -> None:
        """Playbook §5: a dup row whose parent was rejected MUST classify
        as rejected, not duplicate. Otherwise reject-rate math is inflated."""
        status = "Rejected (duplicate of rejected original)"
        self.assertEqual(self.mod.normalize_outcome(status), "rejected")

    # --- dup-of-in-review → in_review ----------------------------------
    def test_duplicate_in_review_normalizes_to_in_review(self) -> None:
        """A dup row whose parent is still In Review inherits in_review."""
        status = "In Review (duplicate, 5 finders; inheriting parent outcome)"
        self.assertEqual(self.mod.normalize_outcome(status), "in_review")

    # --- dup-of-accepted → accepted ------------------------------------
    def test_duplicate_of_paid_normalizes_to_accepted(self) -> None:
        """A dup row whose parent was paid/accepted inherits accepted."""
        status = "Accepted (duplicate, 3 finders; inheriting parent paid outcome)"
        self.assertEqual(self.mod.normalize_outcome(status), "accepted")

    # --- pure duplicate (parent unknown) → duplicate --------------------
    def test_pure_duplicate_without_parent_signal_stays_duplicate(self) -> None:
        """When no parent-outcome token is present, fall back to duplicate.
        This is the only case where `duplicate` bucket is populated."""
        status = "Duplicate (5 finders)"
        self.assertEqual(self.mod.normalize_outcome(status), "duplicate")

    # --- hard-negative: duplicate-only bucket is narrow -----------------
    def test_classifier_never_collapses_a_rejected_dup_to_duplicate(self) -> None:
        """Explicit hard-negative: the pre-fix bug would have returned
        'duplicate' here because 'duplicate' was checked before 'rejected'.
        Lock the post-fix precedence."""
        for status in (
            "REJECTED — duplicate (5 finders)",
            "rejected + dupe",
            "Out of scope + duplicate of already-OOS original",
        ):
            with self.subTest(status=status):
                self.assertEqual(self.mod.normalize_outcome(status), "rejected")

    # --- classifier order sanity ---------------------------------------
    def test_accepted_wins_over_duplicate_and_rejected(self) -> None:
        """Paid/accepted is top precedence so a duplicate-of-paid-but-also-
        some-rejected-word-by-accident still normalizes to accepted."""
        status = "Paid (duplicate, originally rejected + re-accepted)"
        self.assertEqual(self.mod.normalize_outcome(status), "accepted")


if __name__ == "__main__":
    unittest.main()
