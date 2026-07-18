# <!-- r36-rebuttal: chain-synth-broken-invariant-bridge lane; file declared in .auditooor/agent_pathspec.json -->
"""tests/test_chain_synth_broken_invariant_bridge.py - mutation-verified break feed bridge.

Guards the wiring of the mutation-verified break feed
(.auditooor/broken_invariant_ids.json) into chain-synth so that a verified
invariant break becomes a chain seed instead of being silently discarded.

Covers:
  1. collect_broken_invariant_ids reads the feed and promotes ONLY rows with
     mutation_verified == True (R80 - no vacuous seed). A mutation_verified=false
     row, a non-bool truthy value, and a malformed INV id are all rejected.
  2. The feed contribution de-dups against ids already collected from the
     exploit queue / ccia angles.
  3. _input_fingerprints exposes the feed for observability.
  4. seeds_without_template surfaces a verified break with no matching template
     (the seed_had_no_template diagnostic) instead of dropping it.

No network; pure unit tests over a tempdir workspace.
"""
from __future__ import annotations

import importlib.util
import json
import tempfile
import unittest
from pathlib import Path

TOOL = Path(__file__).resolve().parent.parent / "chain-synth-driver.py"


def _load_module():
    spec = importlib.util.spec_from_file_location("chain_synth_driver", TOOL)
    mod = importlib.util.module_from_spec(spec)
    assert spec and spec.loader
    spec.loader.exec_module(mod)
    return mod


csd = _load_module()


def _write_feed(ws: Path, rows: list[dict]) -> None:
    (ws / ".auditooor").mkdir(parents=True, exist_ok=True)
    (ws / csd.BROKEN_INV_FEED_FILE).write_text(
        json.dumps({"broken_invariant_ids": rows}), encoding="utf-8"
    )


class TestBrokenInvariantFeedGate(unittest.TestCase):
    def test_only_mutation_verified_true_becomes_a_seed(self):
        with tempfile.TemporaryDirectory() as d:
            ws = Path(d)
            _write_feed(ws, [
                {"invariant_id": "INV-verified-break", "mutation_verified": True},
                {"invariant_id": "INV-unverified-break", "mutation_verified": False},
            ])
            ids = csd.collect_broken_invariant_ids(ws)
            self.assertIn("INV-verified-break", ids)
            self.assertNotIn("INV-unverified-break", ids)

    def test_non_bool_truthy_value_is_rejected(self):
        # R80: gate is strictly `is True`. The string "true" / 1 must NOT pass,
        # otherwise an unverified break could inject a phantom seed.
        with tempfile.TemporaryDirectory() as d:
            ws = Path(d)
            _write_feed(ws, [
                {"invariant_id": "INV-string-true", "mutation_verified": "true"},
                {"invariant_id": "INV-int-one", "mutation_verified": 1},
                {"invariant_id": "INV-real-true", "mutation_verified": True},
            ])
            ids = csd.collect_broken_invariant_ids(ws)
            self.assertEqual(ids, ["INV-real-true"])

    def test_malformed_inv_id_is_rejected(self):
        with tempfile.TemporaryDirectory() as d:
            ws = Path(d)
            _write_feed(ws, [
                {"invariant_id": "not-an-inv-id", "mutation_verified": True},
                {"invariant_id": "", "mutation_verified": True},
                {"invariant_id": 42, "mutation_verified": True},
                {"invariant_id": "INV-good", "mutation_verified": True},
            ])
            ids = csd.collect_broken_invariant_ids(ws)
            self.assertEqual(ids, ["INV-good"])

    def test_missing_feed_file_is_a_no_op(self):
        with tempfile.TemporaryDirectory() as d:
            ws = Path(d)
            (ws / ".auditooor").mkdir(parents=True, exist_ok=True)
            ids = csd.collect_broken_invariant_ids(ws)
            self.assertEqual(ids, [])

    def test_feed_dedups_against_existing_ids(self):
        with tempfile.TemporaryDirectory() as d:
            ws = Path(d)
            adir = ws / ".auditooor"
            adir.mkdir(parents=True, exist_ok=True)
            # Seed the exploit queue with a real candidate carrying INV-shared.
            (adir / "exploit_queue.json").write_text(json.dumps({
                "queue": [{
                    "lead_id": "LEAD-1",
                    "broken_invariant_ids": ["INV-shared"],
                }],
            }), encoding="utf-8")
            _write_feed(ws, [
                {"invariant_id": "INV-shared", "mutation_verified": True},
                {"invariant_id": "INV-feed-only", "mutation_verified": True},
            ])
            ids = csd.collect_broken_invariant_ids(ws)
            self.assertEqual(ids.count("INV-shared"), 1)
            self.assertIn("INV-feed-only", ids)


class TestInputFingerprintsObservability(unittest.TestCase):
    def test_feed_is_fingerprinted(self):
        with tempfile.TemporaryDirectory() as d:
            ws = Path(d)
            _write_feed(ws, [
                {"invariant_id": "INV-x", "mutation_verified": True},
            ])
            fp = csd._input_fingerprints(ws, [])
            self.assertIn("broken_invariant_feed", fp)


class TestSeedsWithoutTemplate(unittest.TestCase):
    def test_uncovered_seed_is_surfaced(self):
        broken = ["INV-covered", "INV-orphan"]
        matched = [{"member_invariant_ids": ["INV-covered"]}]
        self.assertEqual(
            csd.seeds_without_template(broken, matched), ["INV-orphan"]
        )

    def test_no_templates_means_all_seeds_orphaned(self):
        broken = ["INV-a", "INV-b"]
        self.assertEqual(csd.seeds_without_template(broken, []), ["INV-a", "INV-b"])

    def test_fully_covered_means_none_orphaned(self):
        broken = ["INV-a"]
        matched = [{"matched_invariant_ids": ["INV-a"]}]
        self.assertEqual(csd.seeds_without_template(broken, matched), [])


if __name__ == "__main__":
    unittest.main()
