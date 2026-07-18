"""Tests for tools/outcomes-backfill.py — Loop-13 closeout of T1-PRIORITY-3.

≥4 tests covering:
  1. Idempotency — second run produces identical bytes.
  2. Lane derivation — preserves existing, derives missing, falls back unknown.
  3. fp_reason allow-list — only emitted on FP-shaped outcomes; vocabulary
     is enforced.
  4. Schema preservation — every input key flows through unchanged.

These tests are stdlib-only and offline-safe.
"""
from __future__ import annotations

import importlib.util
import json
import tempfile
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
TOOL = ROOT / "tools" / "outcomes-backfill.py"


def _import():
    spec = importlib.util.spec_from_file_location(
        "outcomes_backfill_test", str(TOOL)
    )
    assert spec is not None and spec.loader is not None
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


def _write_ledger(path: Path, rows: list[dict]) -> None:
    path.write_text(
        "\n".join(json.dumps(r) for r in rows) + "\n",
        encoding="utf-8",
    )


class OutcomesBackfillTests(unittest.TestCase):
    # ---- 1. idempotency -------------------------------------------------
    def test_backfill_is_idempotent(self) -> None:
        mod = _import()
        rows = [
            {
                "workspace": "polymarket",
                "outcome": "pending",
                "title": "row 1",
                "source": "projects/polymarket/submissions/SUBMISSIONS.md",
            },
            {
                "workspace": "base-azul",
                "outcome": "rejected",
                "production_path_blockers_cleared": "no:unrealistic-bounds",
                "title": "row 2",
                "lane": "source-mine",
            },
            {
                "engagement": "centrifuge",
                "outcome": "withdrawn",
                "production_path_blockers_cleared": "no:operator-killed-pre-submit",
                "title": "row 3",
            },
        ]
        with tempfile.TemporaryDirectory() as td:
            path = Path(td) / "outcomes.jsonl"
            _write_ledger(path, rows)

            # First run.
            self.assertEqual(mod.main(["--ledger", str(path)]), 0)
            first_bytes = path.read_bytes()

            # Second run on already-backfilled file -> identical bytes.
            self.assertEqual(mod.main(["--ledger", str(path)]), 0)
            second_bytes = path.read_bytes()

            self.assertEqual(first_bytes, second_bytes,
                             "backfill is not idempotent: byte diff on second run")

            # Third run for paranoia.
            self.assertEqual(mod.main(["--ledger", str(path)]), 0)
            self.assertEqual(path.read_bytes(), first_bytes)

    # ---- 2. lane derivation --------------------------------------------
    def test_lane_derivation(self) -> None:
        mod = _import()
        # Existing lane preserved.
        self.assertEqual(
            mod.derive_lane({"lane": "source-mine", "workspace": "polymarket"}),
            "source-mine",
        )
        # Polymarket submission -> polymarket-source-mine.
        self.assertEqual(
            mod.derive_lane({
                "workspace": "polymarket",
                "source": "projects/polymarket/submissions/SUBMISSIONS.md",
            }),
            "polymarket-source-mine",
        )
        # Polymarket without submission source still maps to polymarket lane.
        self.assertEqual(
            mod.derive_lane({"workspace": "polymarket"}),
            "polymarket-source-mine",
        )
        # Base-azul.
        self.assertEqual(
            mod.derive_lane({"workspace": "base-azul"}),
            "base-azul-source-mine",
        )
        # Centrifuge stub.
        self.assertEqual(
            mod.derive_lane({"engagement": "centrifuge"}),
            "centrifuge-historical-stub",
        )
        # Unknown fallback.
        self.assertEqual(mod.derive_lane({}), "unknown")
        # Whitespace-only existing lane -> derive instead.
        self.assertEqual(
            mod.derive_lane({"lane": "  ", "workspace": "polymarket"}),
            "polymarket-source-mine",
        )

    # ---- 3. fp_reason allow-list + outcome filter -----------------------
    def test_fp_reason_allow_list_and_outcome_filter(self) -> None:
        mod = _import()
        # Non-FP outcome -> None.
        self.assertIsNone(mod.derive_fp_reason({"outcome": "pending"}))
        self.assertIsNone(mod.derive_fp_reason({"outcome": "in_review"}))
        self.assertIsNone(mod.derive_fp_reason({}))
        self.assertIsNone(
            mod.derive_fp_reason({"outcome": "duplicate_of_accepted"})
        )

        # FP-shaped + recognized blocker slug -> mapped category.
        self.assertEqual(
            mod.derive_fp_reason({
                "outcome": "rejected",
                "production_path_blockers_cleared":
                    "no:event-only-cosmetic",
            }),
            "event_only_cosmetic",
        )
        self.assertEqual(
            mod.derive_fp_reason({
                "outcome": "withdrawn",
                "production_path_blockers_cleared":
                    "no:operator-killed-pre-submit",
            }),
            "operator_killed_pre_submit",
        )
        # FP-shaped, no signal -> "unknown".
        self.assertEqual(
            mod.derive_fp_reason({"outcome": "rejected"}),
            "unknown",
        )
        # Bare duplicate w/o richer signal -> duplicate_of_other_submission.
        self.assertEqual(
            mod.derive_fp_reason({"outcome": "duplicate"}),
            "duplicate_of_other_submission",
        )
        # OOS rejection text -> oos_path_hallucination.
        self.assertEqual(
            mod.derive_fp_reason({
                "outcome": "rejected",
                "rejection_reason": "out of scope per audit rubric",
            }),
            "oos_path_hallucination",
        )
        # Pre-existing allow-listed value preserved.
        self.assertEqual(
            mod.derive_fp_reason({
                "outcome": "rejected",
                "fp_reason": "severity_overclaim",
            }),
            "severity_overclaim",
        )
        # Pre-existing non-allow-listed value normalized to "unknown".
        self.assertEqual(
            mod.derive_fp_reason({
                "outcome": "rejected",
                "fp_reason": "made_up_category_42",
            }),
            "unknown",
        )

        # Allow-list integrity: every emitted value is in ALLOWED_FP_REASONS.
        sample_inputs = [
            {"outcome": "rejected"},
            {"outcome": "withdrawn"},
            {"outcome": "duplicate"},
            {"outcome": "rejected",
             "production_path_blockers_cleared":
                 "no:reconstructible-from-erc1155-batch"},
            {"outcome": "rejected",
             "production_path_blockers_cleared":
                 "no:closed-by-self-assessment-not-a-vulnerability"},
            {"outcome": "rejected",
             "production_path_blockers_cleared": "no:nonexistent-slug-xyz"},
        ]
        for row in sample_inputs:
            fp = mod.derive_fp_reason(row)
            self.assertIsNotNone(fp)
            self.assertIn(fp, mod.ALLOWED_FP_REASONS,
                          f"row {row} produced disallowed fp_reason {fp!r}")

    # ---- 4. schema preservation ----------------------------------------
    def test_schema_preservation(self) -> None:
        mod = _import()
        original = {
            "workspace": "polymarket",
            "outcome": "rejected",
            "production_path_blockers_cleared": "no:unrealistic-bounds",
            "title": "test row",
            "severity": "Low",
            "extra_field": "preserve-me",
            "nested": {"a": 1, "b": [2, 3]},
        }
        backfilled = mod.backfill_row(original)
        # Every original key survives with its original value.
        for k, v in original.items():
            self.assertEqual(backfilled[k], v,
                             f"key {k!r} was mutated by backfill_row")
        # New keys added.
        self.assertEqual(backfilled["lane"], "polymarket-source-mine")
        self.assertEqual(backfilled["fp_reason"], "unrealistic_bounds")
        # Non-FP outcome -> fp_reason is null.
        non_fp = mod.backfill_row({"outcome": "pending", "workspace": "polymarket"})
        self.assertIsNone(non_fp["fp_reason"])
        # Original dict was not mutated.
        self.assertNotIn("lane", original)
        self.assertNotIn("fp_reason", original)

    # ---- 5. end-to-end on real-shaped sample ----------------------------
    def test_end_to_end_emits_lane_and_fp_distribution(self) -> None:
        mod = _import()
        rows = [
            {"workspace": "polymarket", "outcome": "pending", "title": "p1"},
            {"workspace": "polymarket", "outcome": "rejected", "title": "p2"},
            {"workspace": "base-azul", "outcome": "withdrawn",
             "lane": "source-mine",
             "production_path_blockers_cleared":
                 "no:withdrawn-after-precondition-check",
             "title": "ba1"},
            {"engagement": "centrifuge", "outcome": "pending",
             "title": "centrifuge-stub"},
            {"workspace": "polymarket", "outcome": "duplicate",
             "title": "p-dupe"},
        ]
        with tempfile.TemporaryDirectory() as td:
            path = Path(td) / "outcomes.jsonl"
            _write_ledger(path, rows)
            self.assertEqual(mod.main(["--ledger", str(path)]), 0)

            # Re-read and verify each row has lane + fp_reason.
            with path.open(encoding="utf-8") as f:
                out = [json.loads(line) for line in f if line.strip()]
            self.assertEqual(len(out), len(rows))
            for r in out:
                self.assertIn("lane", r)
                self.assertIn("fp_reason", r)
            # The withdrawn row carries the mapped fp_reason.
            withdrawn = next(r for r in out if r.get("title") == "ba1")
            self.assertEqual(withdrawn["fp_reason"],
                             "withdrawn_after_precondition_check")
            # Pending rows have null fp_reason.
            pending = next(r for r in out if r.get("title") == "p1")
            self.assertIsNone(pending["fp_reason"])
            # Lane distribution covers both polymarket and base-azul.
            lanes = {r["lane"] for r in out}
            self.assertIn("polymarket-source-mine", lanes)
            self.assertIn("source-mine", lanes)  # preserved
            self.assertIn("centrifuge-historical-stub", lanes)


if __name__ == "__main__":
    unittest.main()
