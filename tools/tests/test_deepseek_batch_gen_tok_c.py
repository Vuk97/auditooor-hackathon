"""Tests for tools/deepseek-batch-gen-tok-c.py.

<!-- r36-rebuttal: lane-DEEPSEEK-BATCH-GEN registered in .auditooor/agent_pathspec.json -->
"""
from __future__ import annotations

import importlib.util
import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
TOOL = ROOT / "tools" / "deepseek-batch-gen-tok-c.py"


def _load_module():
    spec = importlib.util.spec_from_file_location("ds_batch_gen_tok_c", TOOL)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


M = _load_module()


SAMPLE_TAXONOMY = {
    "classes": [
        {
            "attack_class": "reentrancy-cross-function",
            "subtrees": ["solidity_findings"],
            "total_records": 250,
            "tier1_count": 30,
            "tier2_count": 220,
        },
        {
            "attack_class": "missing-slippage",
            "subtrees": ["solidity_findings", "amm_findings"],
            "total_records": 120,
            "tier1_count": 10,
            "tier2_count": 110,
        },
        {
            "attack_class": "rare-orphan-class",
            "subtrees": ["solidity_findings"],
            "total_records": 5,
            "tier1_count": 0,
            "tier2_count": 5,
        },
    ]
}


def _write_json(path: Path, data: dict) -> None:
    path.write_text(json.dumps(data))


class TestLoadTaxonomy(unittest.TestCase):
    def test_loads_classes_from_dict(self):
        with tempfile.TemporaryDirectory() as td:
            p = Path(td) / "tax.json"
            _write_json(p, SAMPLE_TAXONOMY)
            recs = M.load_taxonomy(p)
            self.assertEqual(len(recs), 3)

    def test_loads_list_top_level(self):
        with tempfile.TemporaryDirectory() as td:
            p = Path(td) / "tax.json"
            _write_json(p, {"x": "y"})  # just a dict; load_taxonomy returns []
            # Now write a list directly.
            p.write_text(json.dumps(SAMPLE_TAXONOMY["classes"]))
            recs = M.load_taxonomy(p)
            self.assertEqual(len(recs), 3)


class TestBuildTaskRecord(unittest.TestCase):
    def test_record_shape(self):
        rec = M.build_task_record(
            idx=1, cls=SAMPLE_TAXONOMY["classes"][0],
            task_id_prefix="tok_c_hypothesis_gen",
            verification_tier="tier-3-synthetic-taxonomy-anchored",
            max_input_tokens=4000, max_output_tokens=2000,
        )
        self.assertEqual(rec["task_id"], "tok_c_hypothesis_gen_0001")
        self.assertEqual(rec["task_type"], "tok_c_hypothesis_gen")
        self.assertIn("reentrancy-cross-function", rec["prompt"])
        self.assertEqual(rec["meta"]["attack_class"], "reentrancy-cross-function")
        self.assertEqual(rec["meta"]["total_records"], 250)


class TestDryRun(unittest.TestCase):
    def test_dry_run(self):
        with tempfile.TemporaryDirectory() as td:
            src = Path(td) / "tax.json"
            _write_json(src, SAMPLE_TAXONOMY)
            out_dir = Path(td) / "out"
            res = subprocess.run(
                [sys.executable, str(TOOL),
                 "--source", str(src),
                 "--output-dir", str(out_dir),
                 "--min-records", "20",
                 "--max-batch-size", "5",
                 "--dry-run", "--json"],
                capture_output=True, text=True, timeout=30,
            )
            self.assertEqual(res.returncode, 0, msg=res.stderr)
            data = json.loads(res.stdout)
            # Orphan class (5 records) is filtered out via --min-records 20.
            self.assertEqual(data["records_emitted"], 2)
            self.assertFalse(out_dir.exists())


class TestMinRecordsFilter(unittest.TestCase):
    def test_min_records_filters_orphans(self):
        with tempfile.TemporaryDirectory() as td:
            src = Path(td) / "tax.json"
            _write_json(src, SAMPLE_TAXONOMY)
            out_dir = Path(td) / "out"
            res = subprocess.run(
                [sys.executable, str(TOOL),
                 "--source", str(src),
                 "--output-dir", str(out_dir),
                 "--min-records", "100",
                 "--json"],
                capture_output=True, text=True, timeout=30,
            )
            self.assertEqual(res.returncode, 0, msg=res.stderr)
            data = json.loads(res.stdout)
            # Only reentrancy (250) and missing-slippage (120) qualify.
            self.assertEqual(data["records_emitted"], 2)


class TestSmallBatchWrites(unittest.TestCase):
    def test_small_batch(self):
        with tempfile.TemporaryDirectory() as td:
            src = Path(td) / "tax.json"
            _write_json(src, SAMPLE_TAXONOMY)
            out_dir = Path(td) / "out"
            res = subprocess.run(
                [sys.executable, str(TOOL),
                 "--source", str(src),
                 "--output-dir", str(out_dir),
                 "--min-records", "20",
                 "--json"],
                capture_output=True, text=True, timeout=30,
            )
            self.assertEqual(res.returncode, 0, msg=res.stderr)
            data = json.loads(res.stdout)
            self.assertEqual(data["status"], "ok")
            out_path = Path(data["output_path"])
            self.assertTrue(out_path.exists())


class TestSchemaValidation(unittest.TestCase):
    def test_emitted_shape(self):
        with tempfile.TemporaryDirectory() as td:
            src = Path(td) / "tax.json"
            _write_json(src, SAMPLE_TAXONOMY)
            out_dir = Path(td) / "out"
            res = subprocess.run(
                [sys.executable, str(TOOL),
                 "--source", str(src),
                 "--output-dir", str(out_dir),
                 "--min-records", "20",
                 "--json"],
                capture_output=True, text=True, timeout=30,
            )
            self.assertEqual(res.returncode, 0, msg=res.stderr)
            data = json.loads(res.stdout)
            for ln in Path(data["output_path"]).read_text().strip().split("\n"):
                rec = json.loads(ln)
                for k in ("task_id", "task_type", "prompt",
                          "max_input_tokens", "max_output_tokens",
                          "verification_tier_target", "meta"):
                    self.assertIn(k, rec)


class TestPromptTemplateInsertion(unittest.TestCase):
    def test_class_name_in_prompt(self):
        cls = {
            "attack_class": "unique-marker-class-xyz",
            "subtrees": ["foo"],
            "total_records": 100,
            "tier1_count": 5,
            "tier2_count": 95,
        }
        rec = M.build_task_record(
            idx=1, cls=cls, task_id_prefix="tok_c_hypothesis_gen",
            verification_tier="tier-3-synthetic-taxonomy-anchored",
            max_input_tokens=4000, max_output_tokens=2000,
        )
        self.assertIn("unique-marker-class-xyz", rec["prompt"])


if __name__ == "__main__":
    unittest.main()
