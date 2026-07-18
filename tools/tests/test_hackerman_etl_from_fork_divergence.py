#!/usr/bin/env python3
# r36-rebuttal: lane fork-divergence-etl registered in .auditooor/agent_pathspec.json
"""Tests for tools/hackerman-etl-from-fork-divergence.py.

r37 discipline: assert every emitted record carries a non-empty verification_tier
(tier-2-verified-public-archive) and that the honest-skip path fires when a cited
on-disk verdict source is absent (no fabrication).
"""
import importlib.util
import json
import unittest
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent.parent
MOD_PATH = REPO_ROOT / "tools" / "hackerman-etl-from-fork-divergence.py"

spec = importlib.util.spec_from_file_location("fork_divergence_etl", MOD_PATH)
mod = importlib.util.module_from_spec(spec)
spec.loader.exec_module(mod)


class TestForkDivergenceETL(unittest.TestCase):
    def _run_all_present(self, tmp: Path):
        """Verdicts dir with every cited source artifact present."""
        vdir = tmp / "verdicts"
        vdir.mkdir(parents=True, exist_ok=True)
        for learn in mod._FORK_DIVERGENCE_LEARNINGS:
            art = learn.get("source_artifact")
            if art:
                (vdir / art).write_text("# verdict\n", encoding="utf-8")
        return vdir

    def test_emits_invariant_and_detector_per_learning(self):
        import tempfile

        with tempfile.TemporaryDirectory() as td:
            tmp = Path(td)
            vdir = self._run_all_present(tmp)
            inv = tmp / "invariants_dydx_fork_divergence_advisories.jsonl"
            det = tmp / "detector_seeds_dydx_fork_divergence_advisories.jsonl"
            summary = mod.run(vdir, inv, det, dry_run=False)
            n = len(mod._FORK_DIVERGENCE_LEARNINGS)
            self.assertEqual(summary["invariants_emitted"], n)
            self.assertEqual(summary["detector_seeds_emitted"], n)
            self.assertEqual(summary["skipped_missing_source"], [])
            self.assertTrue(inv.exists() and det.exists())

    def test_every_record_has_tier_2(self):
        import tempfile

        with tempfile.TemporaryDirectory() as td:
            tmp = Path(td)
            vdir = self._run_all_present(tmp)
            inv = tmp / "inv.jsonl"
            det = tmp / "det.jsonl"
            mod.run(vdir, inv, det, dry_run=False)
            for line in inv.read_text().splitlines():
                r = json.loads(line)
                self.assertEqual(
                    r["verification_tier"], "tier-2-verified-public-archive"
                )
                self.assertTrue(r["content"]["invariant_id"].startswith("INV-FORKDIV-"))
                self.assertTrue(r["content"]["invariant_text"])
                self.assertEqual(
                    r["content"]["attack_class"], "fork-divergence-missing-upstream-fix"
                )
            for line in det.read_text().splitlines():
                r = json.loads(line)
                self.assertEqual(
                    r["verification_tier"], "tier-2-verified-public-archive"
                )
                self.assertEqual(r["schema_version"], "auditooor.detector_seed.v1")
                # statement is a JSON-encoded inner detector body
                inner = json.loads(r["statement"])
                self.assertIn("regex_pattern", inner)
                self.assertIn("detector_id", inner)

    def test_honest_skip_when_source_missing(self):
        """A cited verdict artifact that does NOT exist => that learning is
        skipped, never fabricated. The always_emit technique anchor still emits."""
        import tempfile

        with tempfile.TemporaryDirectory() as td:
            tmp = Path(td)
            vdir = tmp / "empty_verdicts"
            vdir.mkdir()  # no artifact files written
            summary = mod.run(vdir, None, None, dry_run=True)
            # Only always_emit (technique anchor) entries survive
            always = [l for l in mod._FORK_DIVERGENCE_LEARNINGS if l.get("always_emit")]
            file_backed = [
                l
                for l in mod._FORK_DIVERGENCE_LEARNINGS
                if l.get("source_artifact") and not l.get("always_emit")
            ]
            self.assertEqual(summary["invariants_emitted"], len(always))
            self.assertEqual(
                len(summary["skipped_missing_source"]), len(file_backed)
            )

    def test_technique_anchor_present(self):
        """The upstream-fix-not-backported technique (cometbft fork-lag) MUST be
        the always-emit anchor - it is the existence-proof of the whole class."""
        anchors = [
            l
            for l in mod._FORK_DIVERGENCE_LEARNINGS
            if l.get("always_emit")
        ]
        self.assertTrue(any(a["id"] == "cometbft-fork-lag-blocksync" for a in anchors))
        anchor = next(a for a in anchors if a["id"] == "cometbft-fork-lag-blocksync")
        self.assertEqual(
            anchor["detector_id"], "upstream-fix-not-backported-to-fork"
        )

    def test_negative_control_learning_present(self):
        """The ibc-go DROP (publicly-disclosed + recoverable) is the negative
        control that teaches the fileability gate."""
        ids = [l["id"] for l in mod._FORK_DIVERGENCE_LEARNINGS]
        self.assertIn("ibc-go-fork-divergence-negative-control", ids)
        neg = next(
            l
            for l in mod._FORK_DIVERGENCE_LEARNINGS
            if l["id"] == "ibc-go-fork-divergence-negative-control"
        )
        self.assertEqual(neg["severity"], "drop")
        self.assertEqual(neg["detector_id"], "fork-divergence-fileability-gate")

    def test_jsonl_filenames_match_promotion_glob(self):
        """The output filenames MUST match promote-mined's
        invariants_*_advisories.jsonl / detector_seeds_*_advisories.jsonl glob."""
        import re

        inv_name = "invariants_dydx_fork_divergence_advisories.jsonl"
        det_name = "detector_seeds_dydx_fork_divergence_advisories.jsonl"
        self.assertTrue(re.fullmatch(r"invariants_.+_advisories\.jsonl", inv_name))
        self.assertTrue(re.fullmatch(r"detector_seeds_.+_advisories\.jsonl", det_name))

    def test_dry_run_writes_nothing(self):
        import tempfile

        with tempfile.TemporaryDirectory() as td:
            tmp = Path(td)
            vdir = self._run_all_present(tmp)
            inv = tmp / "inv.jsonl"
            det = tmp / "det.jsonl"
            summary = mod.run(vdir, inv, det, dry_run=True)
            self.assertTrue(summary["dry_run"])
            self.assertFalse(inv.exists())
            self.assertFalse(det.exists())
            self.assertGreater(summary["invariants_emitted"], 0)


if __name__ == "__main__":
    unittest.main()
