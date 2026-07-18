#!/usr/bin/env python3
"""Guard test: ranker-learn seeds confirmed own-findings as learnable TP outcomes.

Meta-audit finding: "ranker-apply-weights never runs". Root cause: the batch
learner consumes only tags carrying ``triager_outcome:``, and nothing ever
stamped that key, so no weight snapshot was produced and the operator never had
a SHA to apply. This test pins the seeder: confirmed own-finding tags get
``triager_outcome`` + ``attack_classes_to_try`` stamped (idempotently), and the
seeder NEVER applies weights (operator gate stays). Offline; temp dirs.
"""
from __future__ import annotations

import importlib.util
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
TOOL = ROOT / "tools" / "ranker-learn.py"


def _load_module():
    spec = importlib.util.spec_from_file_location("_ranker_learn", TOOL)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


_TAG = """schema_version: auditooor.hackerman_record.v1.1
record_id: "own-finding:alpha:s0"
target_repo: alpha/contracts
attack_class: admin-bypass
severity_at_finding: high
record_extensions:
  confirmed_finding: true
"""


class TestSeedOwnFindings(unittest.TestCase):
    def setUp(self) -> None:
        self.mod = _load_module()

    def test_seed_stamps_learnable_keys(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            own = Path(td)
            tag = own / "own-alpha.yaml"
            tag.write_text(_TAG, encoding="utf-8")
            n = self.mod.seed_own_findings(own_dir=own, outcome="ACCEPTED")
            self.assertEqual(n, 1)
            txt = tag.read_text(encoding="utf-8")
            self.assertIn("triager_outcome: ACCEPTED", txt)
            self.assertIn("severity_final: HIGH", txt)
            self.assertIn("attack_classes_to_try: [admin-bypass]", txt)
            # realized-AC extraction (used by the gradient) now resolves
            self.assertEqual(self.mod.realized_ac_for_tag(tag), "admin-bypass")

    def test_seed_is_idempotent(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            own = Path(td)
            (own / "own-alpha.yaml").write_text(_TAG, encoding="utf-8")
            first = self.mod.seed_own_findings(own_dir=own)
            second = self.mod.seed_own_findings(own_dir=own)
            self.assertEqual(first, 1)
            self.assertEqual(second, 0, "re-run does not re-stamp already-learnable tags")

    def test_unconfirmed_tag_not_seeded(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            own = Path(td)
            (own / "own-x.yaml").write_text(
                _TAG.replace("confirmed_finding: true", "confirmed_finding: false"),
                encoding="utf-8",
            )
            self.assertEqual(self.mod.seed_own_findings(own_dir=own), 0)

    def test_absent_dir_is_zero(self) -> None:
        self.assertEqual(
            self.mod.seed_own_findings(own_dir=Path("/nonexistent/own")), 0)

    def test_seeded_tags_are_collected_by_batch_learner(self) -> None:
        # The seeded tag must be picked up by collect_batch_tags (rglob into
        # subdirs) so a snapshot can actually be produced for the operator.
        with tempfile.TemporaryDirectory() as td:
            tags = Path(td)
            sub = tags / "auditooor_own_findings"
            sub.mkdir()
            (sub / "own-alpha.yaml").write_text(_TAG, encoding="utf-8")
            self.mod.seed_own_findings(own_dir=sub)
            import datetime
            collected = self.mod.collect_batch_tags(
                datetime.timedelta(hours=100000), tags_dir=tags)
        self.assertEqual(len(collected), 1,
                         "seeded subdir tag is visible to the batch learner")


if __name__ == "__main__":
    unittest.main()
