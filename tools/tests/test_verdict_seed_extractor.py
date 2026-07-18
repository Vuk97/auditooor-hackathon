#!/usr/bin/env python3
from __future__ import annotations

import importlib.util
import sys
import tempfile
import types
import unittest
from pathlib import Path

import yaml


ROOT = Path(__file__).resolve().parents[2]
TOOL = ROOT / "tools" / "verdict-seed-extractor.py"
FIX = Path(__file__).parent / "fixtures" / "verdict_seed_extractor"


def _load_module() -> types.ModuleType:
    spec = importlib.util.spec_from_file_location("verdict_seed_extractor", TOOL)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


MOD = _load_module()


class VerdictSeedExtractorTest(unittest.TestCase):
    def _run(self, dry_run: bool = False) -> tuple[dict, Path]:
        tmp = Path(tempfile.mkdtemp())
        glob = str(FIX / "*.md")
        summary = MOD.run(globs=[glob], out_dir=tmp, dry_run=dry_run)
        return summary, tmp

    def test_section_marker_detection_emits_seeds(self) -> None:
        summary, out = self._run()
        # sample_verdict_with_sections.md has 4 section markers: Engineering Yield,
        # Detector Seeds, Recommendation, Future work.
        self.assertGreaterEqual(summary["seeds_emitted"], 4)
        emitted = list(out.rglob("*_seed.yaml"))
        self.assertTrue(
            any("engineering-yield" in p.name for p in emitted),
            f"missing engineering-yield seed; saw {[p.name for p in emitted]}",
        )
        self.assertTrue(any("detector-seed" in p.name for p in emitted))
        self.assertTrue(any("recommendation" in p.name for p in emitted))
        self.assertTrue(any("future-work" in p.name for p in emitted))

    def test_language_hint_detection(self) -> None:
        _summary, out = self._run()
        # Engineering Yield section mentions iter.go => go bucket.
        go_seeds = list((out / "go").glob("*_seed.yaml")) if (out / "go").exists() else []
        self.assertTrue(go_seeds, "expected at least one go-bucket seed")
        payload = yaml.safe_load(go_seeds[0].read_text(encoding="utf-8"))
        self.assertEqual(payload["language_hint"], "go")
        self.assertIn("origin_verdict", payload)
        self.assertIn("empirical_anchor", payload)
        self.assertIn("extracted_at", payload)

    def test_parity_precedent_regex_extractor(self) -> None:
        summary, out = self._run()
        self.assertGreaterEqual(summary["parity_precedent"], 1)
        emitted = list(out.glob("parity_precedent_*.yaml"))
        self.assertTrue(emitted, "expected parity_precedent_*.yaml seed")
        payload = yaml.safe_load(emitted[0].read_text(encoding="utf-8"))
        self.assertEqual(payload["extractor_id"], "parity-precedent")
        self.assertEqual(payload["detector_class_hint"], "regex")

    def test_but_for_regex_extractor(self) -> None:
        summary, out = self._run()
        self.assertGreaterEqual(summary["but_for"], 1)
        emitted = list(out.glob("but_for_*.yaml"))
        self.assertTrue(emitted, "expected but_for_*.yaml seed")
        payload = yaml.safe_load(emitted[0].read_text(encoding="utf-8"))
        self.assertEqual(payload["extractor_id"], "but-for")

    def test_synthetic_driver_regex_extractor(self) -> None:
        summary, out = self._run()
        self.assertGreaterEqual(summary["synthetic_driver"], 1)
        emitted = list(out.glob("synthetic_driver_*.yaml"))
        self.assertTrue(emitted, "expected synthetic_driver_*.yaml seed")

    def test_dry_run_emits_no_files(self) -> None:
        summary, out = self._run(dry_run=True)
        self.assertGreater(summary["seeds_emitted"], 0)
        # No YAML files should land on disk.
        leftovers = list(out.rglob("*.yaml"))
        self.assertEqual(leftovers, [], f"dry-run wrote files: {leftovers}")

    def test_empty_verdict_yields_no_seeds(self) -> None:
        tmp = Path(tempfile.mkdtemp())
        summary = MOD.run(
            globs=[str(FIX / "empty_verdict.md")], out_dir=tmp, dry_run=False
        )
        self.assertEqual(summary["seeds_emitted"], 0)


if __name__ == "__main__":
    unittest.main()
