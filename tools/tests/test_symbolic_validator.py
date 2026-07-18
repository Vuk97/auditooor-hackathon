#!/usr/bin/env python3
"""Kimi 20/10 Step 4 — tests for tools/symbolic-execution-validator.py.

Coverage:
  * locked status vocabulary (5 states, no `pass`)
  * runner-status alias mapping (`pass` → `no-counterexample`)
  * single-run manifest emission for a missing workspace (skipped)
  * single-run manifest emission for a missing draft (skipped)
  * dry-run path emits skipped + dry-run reason
  * aggregate JSON shape + threshold-gate logic
  * blocking_eligible respects MIN_RUNS / MIN_ENGAGEMENTS / FP_RATE_THRESHOLD
  * compute_fp_rate is conservative when no decisive runs exist
  * vocab CLI subcommand prints exactly the locked tuple
"""
from __future__ import annotations

import importlib.util
import json
import sys
import tempfile
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
MODULE_PATH = ROOT / "tools" / "symbolic-execution-validator.py"


def _load_module():
    spec = importlib.util.spec_from_file_location("symbolic_validator", MODULE_PATH)
    assert spec is not None and spec.loader is not None
    mod = importlib.util.module_from_spec(spec)
    sys.modules["symbolic_validator"] = mod
    spec.loader.exec_module(mod)
    return mod


symval = _load_module()


class StatusVocabularyTests(unittest.TestCase):
    def test_locked_vocabulary_is_exactly_five_states(self):
        self.assertEqual(
            symval.STATUS_VOCAB,
            (
                "no-counterexample",
                "counterexample",
                "timeout",
                "skipped",
                "error",
            ),
        )

    def test_pass_alias_collapses_to_no_counterexample(self):
        self.assertEqual(symval.normalize_verdict("pass"), "no-counterexample")
        self.assertEqual(symval.normalize_verdict("PASS"), "no-counterexample")

    def test_unknown_verdict_falls_back_to_error(self):
        self.assertEqual(symval.normalize_verdict("flaky"), "error")
        self.assertEqual(symval.normalize_verdict(""), "error")
        self.assertEqual(symval.normalize_verdict(None), "error")

    def test_is_locked_vocab_recognises_each_state(self):
        for v in symval.STATUS_VOCAB:
            self.assertTrue(symval.is_locked_vocab(v))
        self.assertFalse(symval.is_locked_vocab("pass"))
        self.assertFalse(symval.is_locked_vocab("anything-else"))


class SingleRunManifestTests(unittest.TestCase):
    def test_missing_workspace_produces_skipped_manifest(self):
        with tempfile.TemporaryDirectory() as td:
            out = Path(td) / "out.json"
            manifest = symval.run_validation(
                workspace=Path(td) / "does-not-exist",
                draft=Path(td) / "no-draft.md",
                angle="A-AUTH",
                engagement="dummy",
                out_path=out,
                runner=ROOT / "tools" / "symbolic-runner.sh",
                timeout_sec=5,
            )
        self.assertEqual(manifest["verdict"], "skipped")
        self.assertIn("workspace not found", manifest["skipped_reason"] or "")

    def test_missing_draft_produces_skipped_manifest(self):
        with tempfile.TemporaryDirectory() as td:
            ws = Path(td) / "ws"
            ws.mkdir()
            out = Path(td) / "out.json"
            manifest = symval.run_validation(
                workspace=ws,
                draft=ws / "missing.md",
                angle="A-AUTH",
                engagement="dummy",
                out_path=out,
                runner=ROOT / "tools" / "symbolic-runner.sh",
                timeout_sec=5,
            )
        self.assertEqual(manifest["verdict"], "skipped")
        self.assertIn("draft not found", manifest["skipped_reason"] or "")

    def test_dry_run_emits_skipped_reason(self):
        with tempfile.TemporaryDirectory() as td:
            ws = Path(td) / "ws"
            ws.mkdir()
            draft = ws / "draft.md"
            draft.write_text("dummy")
            out = Path(td) / "out.json"
            manifest = symval.run_validation(
                workspace=ws,
                draft=draft,
                angle="A-AUTH",
                engagement="dummy",
                out_path=out,
                runner=ROOT / "tools" / "symbolic-runner.sh",
                timeout_sec=5,
                dry_run=True,
            )
        # Dry-run path returns skipped only when a backend was discovered;
        # otherwise the skip happens earlier ("no backend installed"). Either
        # way, the verdict must be `skipped` and the reason non-empty.
        self.assertEqual(manifest["verdict"], "skipped")
        self.assertTrue(manifest["skipped_reason"])

    def test_manifest_has_step4_required_keys(self):
        with tempfile.TemporaryDirectory() as td:
            out = Path(td) / "out.json"
            symval.run_validation(
                workspace=Path(td) / "missing",
                draft=Path(td) / "missing.md",
                angle="A-AUTH",
                engagement="poly",
                out_path=out,
                runner=ROOT / "tools" / "symbolic-runner.sh",
                timeout_sec=5,
            )
            data = json.loads(out.read_text())
        for key in (
            "schema_version",
            "engagement",
            "draft",
            "angle",
            "verdict",
            "runtime_ms",
            "counterexample",
            "backend",
            "backend_version",
        ):
            self.assertIn(key, data, f"missing key {key!r}")
        self.assertIn(data["verdict"], symval.STATUS_VOCAB)


class AggregateAndGateTests(unittest.TestCase):
    @staticmethod
    def _write_manifests(directory: Path, runs):
        directory.mkdir(parents=True, exist_ok=True)
        for i, (eng, verdict) in enumerate(runs):
            (directory / f"run-{i:02d}.json").write_text(
                json.dumps(
                    {
                        "engagement": eng,
                        "verdict": verdict,
                        "angle": "A-AUTH",
                    }
                )
            )

    def test_aggregate_shape(self):
        with tempfile.TemporaryDirectory() as td:
            d = Path(td) / "vals"
            self._write_manifests(
                d,
                [
                    ("polymarket", "no-counterexample"),
                    ("polymarket", "counterexample"),
                    ("morpho", "no-counterexample"),
                    ("morpho", "skipped"),
                    ("centrifuge", "no-counterexample"),
                    ("centrifuge", "error"),
                ],
            )
            out = d / "aggregate.json"
            agg = symval.aggregate(d, out)
        self.assertEqual(agg["schema_version"], 1)
        self.assertEqual(agg["total_runs"], 6)
        self.assertEqual(agg["by_verdict"]["no-counterexample"], 3)
        self.assertEqual(agg["by_verdict"]["counterexample"], 1)
        self.assertEqual(agg["by_verdict"]["skipped"], 1)
        self.assertEqual(agg["by_verdict"]["error"], 1)
        self.assertEqual(
            sorted(agg["engagements"]), ["centrifuge", "morpho", "polymarket"]
        )
        # Decisive runs = 6 - 1 - 1 = 4. counterexample = 1 → 0.25.
        self.assertAlmostEqual(agg["fp_rate_estimate"], 0.25, places=4)
        self.assertTrue(agg["blocking_eligible"])

    def test_blocking_gate_requires_three_engagements(self):
        with tempfile.TemporaryDirectory() as td:
            d = Path(td) / "vals"
            self._write_manifests(
                d,
                [
                    ("polymarket", "no-counterexample"),
                    ("polymarket", "no-counterexample"),
                    ("polymarket", "no-counterexample"),
                ],
            )
            agg = symval.aggregate(d, d / "aggregate.json")
        self.assertEqual(agg["total_runs"], 3)
        self.assertEqual(agg["fp_rate_estimate"], 0.0)
        self.assertFalse(agg["blocking_eligible"])

    def test_blocking_gate_blocks_high_fp_rate(self):
        with tempfile.TemporaryDirectory() as td:
            d = Path(td) / "vals"
            self._write_manifests(
                d,
                [
                    ("polymarket", "counterexample"),
                    ("polymarket", "counterexample"),
                    ("morpho", "counterexample"),
                    ("centrifuge", "no-counterexample"),
                ],
            )
            agg = symval.aggregate(d, d / "aggregate.json")
        # 3 CE / 4 decisive = 0.75 > 0.3 → not eligible
        self.assertGreater(agg["fp_rate_estimate"], symval.FP_RATE_THRESHOLD)
        self.assertFalse(agg["blocking_eligible"])

    def test_compute_fp_rate_conservative_with_no_decisive_runs(self):
        manifests = [
            {"verdict": "skipped", "engagement": "x"},
            {"verdict": "skipped", "engagement": "y"},
            {"verdict": "error", "engagement": "z"},
        ]
        # All runs are skipped/error → no decisive evidence → 1.0.
        self.assertEqual(symval.compute_fp_rate(manifests), 1.0)

    def test_aggregate_handles_empty_directory(self):
        with tempfile.TemporaryDirectory() as td:
            agg = symval.aggregate(Path(td), Path(td) / "aggregate.json")
        self.assertEqual(agg["total_runs"], 0)
        self.assertEqual(agg["fp_rate_estimate"], 1.0)
        self.assertFalse(agg["blocking_eligible"])

    def test_thresholds_match_kimi_spec(self):
        self.assertEqual(symval.FP_RATE_THRESHOLD, 0.3)
        self.assertEqual(symval.MIN_RUNS, 3)
        self.assertEqual(symval.MIN_ENGAGEMENTS, 3)


class CliVocabSubcommandTests(unittest.TestCase):
    def test_vocab_subcommand_prints_locked_tuple(self):
        import io

        buf = io.StringIO()
        original_stdout = sys.stdout
        try:
            sys.stdout = buf
            rc = symval.main(["vocab"])
        finally:
            sys.stdout = original_stdout
        self.assertEqual(rc, 0)
        data = json.loads(buf.getvalue())
        self.assertEqual(data["status_vocab"], list(symval.STATUS_VOCAB))


if __name__ == "__main__":
    unittest.main()
