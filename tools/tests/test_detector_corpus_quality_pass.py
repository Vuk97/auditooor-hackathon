from __future__ import annotations

import importlib.util
import json
import sys
import tempfile
import unittest
from pathlib import Path


REPO = Path(__file__).resolve().parents[2]
TOOL = REPO / "tools" / "detector-corpus-quality-pass.py"


def load_tool():
    spec = importlib.util.spec_from_file_location("detector_corpus_quality_pass", TOOL)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


class DetectorCorpusQualityPassTests(unittest.TestCase):
    def test_classifies_dead_reactivated_and_live_paths(self) -> None:
        tool = load_tool()
        root = Path("/tmp/repo")
        self.assertEqual(tool.classify_status(root / "detectors" / "wave17" / "x.py"), "live")
        self.assertEqual(tool.classify_status(root / "detectors" / "fixtures" / "a_broken_case" / "x.py"), "live")
        self.assertEqual(tool.classify_status(root / "detectors" / "wave14_broken" / "x.py"), "broken")
        self.assertEqual(tool.classify_status(root / "detectors" / "wave_graveyard" / "x.py"), "graveyard")
        self.assertEqual(tool.classify_status(root / "detectors" / "wave17" / "_quarantine" / "x.py"), "quarantine")
        self.assertEqual(
            tool.classify_status(root / "detectors" / "wave17_graveyard_reactivated" / "x.py"),
            "reactivated",
        )

    def test_inventory_and_fp_backtest_on_temp_repo(self) -> None:
        tool = load_tool()
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            live_dir = root / "detectors" / "wave17"
            neg_dir = root / "detectors" / "test_fixtures" / "negative"
            broken_dir = root / "detectors" / "wave14_broken"
            quarantine_dir = root / "detectors" / "wave17" / "_quarantine_fp"
            go_dir = root / "detectors" / "go_wave1"
            go_fx = go_dir / "test_fixtures"
            for path in (live_dir, neg_dir, broken_dir, quarantine_dir):
                path.mkdir(parents=True, exist_ok=True)
            go_fx.mkdir(parents=True, exist_ok=True)
            (root / "tools").mkdir(parents=True, exist_ok=True)

            (live_dir / "noisy_detector.py").write_text(
                "\n".join(
                    [
                        '"""',
                        "verification_tier: tier-2-verified-public-archive",
                        '"""',
                        'DETECTOR_NAME = "noisy-detector"',
                        "class Finding:",
                        "    def __init__(self, detector, file, line, message):",
                        "        self.detector = detector",
                        "        self.file = file",
                        "        self.line = line",
                        "        self.message = message",
                        "def scan(source, file_path):",
                        "    if 'clean_hit' in source:",
                        "        return [Finding(DETECTOR_NAME, file_path, 1, 'hit')]",
                        "    return []",
                    ]
                )
                + "\n",
                encoding="utf-8",
            )
            (live_dir / "crashy_detector.py").write_text(
                "\n".join(
                    [
                        'DETECTOR_NAME = "crashy-detector"',
                        "def scan(source, file_path):",
                        "    raise RuntimeError('clean crash')",
                    ]
                )
                + "\n",
                encoding="utf-8",
            )
            (broken_dir / "bad.py").write_text("def nope(:\n", encoding="utf-8")
            (quarantine_dir / "old.py").write_text("verification_tier: tier-5-quarantine\n", encoding="utf-8")
            (root / "tools" / "ast-engine.py").write_text(
                "\n".join(
                    [
                        "class AstEngine:",
                        "    def __init__(self, lang, source):",
                        "        self.lang = lang",
                        "        self.source = source.decode('utf-8', errors='replace')",
                        "    def parse(self):",
                        "        return object()",
                    ]
                )
                + "\n",
                encoding="utf-8",
            )
            (go_dir / "noisy_go.py").write_text(
                "\n".join(
                    [
                        "def run(engine, filepath):",
                        "    if 'go_noise' in engine.source:",
                        "        return [{'line': 1, 'message': 'hit'}]",
                        "    return []",
                    ]
                )
                + "\n",
                encoding="utf-8",
            )
            for idx in range(6):
                marker = "clean_hit" if idx < 4 else "safe"
                target_dir = neg_dir if idx < 3 else root / "detectors" / "test_fixtures"
                target_dir.mkdir(parents=True, exist_ok=True)
                (target_dir / f"clean_{idx}.sol").write_text(f"contract C {{ string s = '{marker}'; }}\n", encoding="utf-8")
                go_marker = "go_noise" if idx < 4 else "safe"
                (go_fx / f"case_{idx}_negative.go").write_text(f"package p\n// {go_marker}\n", encoding="utf-8")

            out_json = root / "reports" / "quality.json"
            out_md = root / "reports" / "quality.md"
            out_tiers = root / "reports" / "tiers.jsonl"
            rc = tool.main(
                [
                    "--repo",
                    str(root),
                    "--out-json",
                    str(out_json),
                    "--out-md",
                    str(out_md),
                    "--out-tiers-jsonl",
                    str(out_tiers),
                    "--fp-backtest",
                    "--max-fp-detectors",
                    "0",
                    "--max-clean-fixtures",
                    "0",
                    "--fp-threshold",
                    "0.5",
                    "--language-fp-backtest",
                    "--language-fp-langs",
                    "go",
                ]
            )
            self.assertEqual(rc, 0)
            payload = json.loads(out_json.read_text(encoding="utf-8"))
            summary = payload["summary"]
            self.assertEqual(summary["total_detector_like_files"], 5)
            self.assertEqual(summary["dead_weight_detector_like_files"], 2)
            self.assertEqual(summary["status_distribution"]["broken"], 1)
            self.assertEqual(summary["status_distribution"]["quarantine"], 1)
            self.assertEqual(summary["verification_tier_distribution"]["tier-2-verified-public-archive"], 1)
            self.assertEqual(summary["verification_tier_distribution"]["tier-5-quarantine"], 1)
            self.assertEqual(summary["survivor_effective_verification_tier_distribution"]["tier-2-verified-public-archive"], 1)
            self.assertEqual(summary["survivor_effective_verification_tier_distribution"]["tier-3-synthetic-taxonomy-anchored"], 2)
            self.assertEqual(summary["survivor_missing_effective_verification_tier_count"], 0)
            self.assertEqual(summary["py_compile_distribution"]["compile_failed"], 1)
            self.assertEqual(summary["fp_quarantine_recommendation_count"], 2)
            self.assertEqual(summary["language_fp_quarantine_recommendation_count"], 1)
            self.assertEqual({row["clean_fixtures_scanned"] for row in payload["fp_backtest"]}, {6})
            self.assertEqual({row["clean_fixtures_scanned"] for row in payload["language_fp_backtest"]}, {6})
            self.assertIn("quarantine_candidate_clean_scan_exception", {row["recommendation"] for row in payload["fp_backtest"]})
            self.assertIn(
                "quarantine_candidate_high_clean_fp",
                {row["recommendation"] for row in payload["language_fp_backtest"]},
            )
            md_text = out_md.read_text(encoding="utf-8")
            self.assertIn("Detector Corpus Quality Pass", md_text)
            self.assertIn("Language Clean-Fixture FP Backtest", md_text)
            self.assertIn("raised exceptions", md_text)
            tier_rows = [json.loads(line) for line in out_tiers.read_text(encoding="utf-8").splitlines()]
            self.assertEqual(len(tier_rows), 3)
            self.assertEqual(
                {row["verification_tier"] for row in tier_rows},
                {"tier-2-verified-public-archive", "tier-3-synthetic-taxonomy-anchored"},
            )
            self.assertFalse((live_dir / "__pycache__").exists())


if __name__ == "__main__":
    unittest.main()
