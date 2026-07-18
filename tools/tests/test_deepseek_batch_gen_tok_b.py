"""Tests for tools/deepseek-batch-gen-tok-b.py.

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
TOOL = ROOT / "tools" / "deepseek-batch-gen-tok-b.py"


def _load_module():
    spec = importlib.util.spec_from_file_location("ds_batch_gen_tok_b", TOOL)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


M = _load_module()


SAMPLE_INVARIANTS = [
    {
        "schema_version": "auditooor.invariant_pilot.v1",
        "invariant_id": "INV-UNI-001",
        "category": "uniqueness",
        "statement": "Signed message MUST be consumable at most once.",
        "target_lang": "any",
        "abstraction_level": "protocol-invariant",
        "commit_point_pattern": "mark-consumed-before-mutation",
        "defense_layer": "consumed_set",
    },
    {
        "invariant_id": "INV-CON-002",
        "category": "conservation",
        "statement": "sum(balances) == totalSupply.",
    },
    {
        "category": "no-id",
        "statement": "Some statement without invariant_id.",
    },
]


def _write_jsonl(path: Path, recs: list) -> None:
    with path.open("w") as fh:
        for r in recs:
            fh.write(json.dumps(r) + "\n")


class TestLoadInvariants(unittest.TestCase):
    def test_loads_valid_records(self):
        with tempfile.TemporaryDirectory() as td:
            p = Path(td) / "inv.jsonl"
            _write_jsonl(p, SAMPLE_INVARIANTS)
            recs = M.load_invariants(p)
            self.assertEqual(len(recs), 3)

    def test_skips_malformed_lines(self):
        with tempfile.TemporaryDirectory() as td:
            p = Path(td) / "inv.jsonl"
            with p.open("w") as fh:
                fh.write(json.dumps(SAMPLE_INVARIANTS[0]) + "\n")
                fh.write("this is not json\n")
                fh.write("\n")  # blank
                fh.write(json.dumps(SAMPLE_INVARIANTS[1]) + "\n")
            recs = M.load_invariants(p)
            self.assertEqual(len(recs), 2)


class TestBuildTaskRecord(unittest.TestCase):
    def test_record_shape(self):
        rec = M.build_task_record(
            idx=7, invariant=SAMPLE_INVARIANTS[0],
            task_id_prefix="tok_b_invariant_lift", target_lang="rust",
            verification_tier="tier-3-synthetic-taxonomy-anchored",
            max_input_tokens=6000, max_output_tokens=1500,
        )
        self.assertEqual(rec["task_id"], "tok_b_invariant_lift_0007")
        self.assertEqual(rec["task_type"], "tok_b_invariant_lift")
        self.assertIn("INV-UNI-001", rec["prompt"])
        self.assertIn("rust", rec["prompt"])
        self.assertEqual(rec["meta"]["invariant_id"], "INV-UNI-001")
        self.assertEqual(rec["meta"]["target_lang"], "rust")


class TestDryRun(unittest.TestCase):
    def test_dry_run_no_file(self):
        with tempfile.TemporaryDirectory() as td:
            src = Path(td) / "inv.jsonl"
            _write_jsonl(src, SAMPLE_INVARIANTS)
            out_dir = Path(td) / "out"
            res = subprocess.run(
                [sys.executable, str(TOOL),
                 "--source", str(src),
                 "--output-dir", str(out_dir),
                 "--max-batch-size", "5",
                 "--dry-run", "--json"],
                capture_output=True, text=True, timeout=30,
            )
            self.assertEqual(res.returncode, 0, msg=res.stderr)
            data = json.loads(res.stdout)
            self.assertEqual(data["status"], "dry-run")
            self.assertEqual(data["records_emitted"], 3)
            self.assertFalse(out_dir.exists())


class TestSmallBatchWrites(unittest.TestCase):
    def test_small_batch(self):
        with tempfile.TemporaryDirectory() as td:
            src = Path(td) / "inv.jsonl"
            _write_jsonl(src, SAMPLE_INVARIANTS[:2])
            out_dir = Path(td) / "out"
            res = subprocess.run(
                [sys.executable, str(TOOL),
                 "--source", str(src),
                 "--output-dir", str(out_dir),
                 "--max-batch-size", "5",
                 "--json"],
                capture_output=True, text=True, timeout=30,
            )
            self.assertEqual(res.returncode, 0, msg=res.stderr)
            data = json.loads(res.stdout)
            self.assertEqual(data["records_emitted"], 2)
            out_path = Path(data["output_path"])
            lines = out_path.read_text().strip().split("\n")
            self.assertEqual(len(lines), 2)


class TestSchemaValidation(unittest.TestCase):
    def test_emitted_shape(self):
        with tempfile.TemporaryDirectory() as td:
            src = Path(td) / "inv.jsonl"
            _write_jsonl(src, SAMPLE_INVARIANTS)
            out_dir = Path(td) / "out"
            res = subprocess.run(
                [sys.executable, str(TOOL),
                 "--source", str(src),
                 "--output-dir", str(out_dir),
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
                self.assertEqual(rec["task_type"], "tok_b_invariant_lift")


class TestPromptTemplateInsertion(unittest.TestCase):
    def test_target_lang_propagates_to_prompt(self):
        rec = M.build_task_record(
            idx=1, invariant=SAMPLE_INVARIANTS[0],
            task_id_prefix="tok_b_invariant_lift", target_lang="move",
            verification_tier="tier-3-synthetic-taxonomy-anchored",
            max_input_tokens=6000, max_output_tokens=1500,
        )
        self.assertIn("move", rec["prompt"])
        self.assertIn("INV-UNI-001", rec["prompt"])


class TestEndToEnd(unittest.TestCase):
    def test_e2e_with_mock_source(self):
        with tempfile.TemporaryDirectory() as td:
            src_dir = Path(td) / "src"
            src_dir.mkdir()
            _write_jsonl(src_dir / "a.jsonl", SAMPLE_INVARIANTS[:2])
            _write_jsonl(src_dir / "b.jsonl", SAMPLE_INVARIANTS[2:])
            out_dir = Path(td) / "out"
            res = subprocess.run(
                [sys.executable, str(TOOL),
                 "--source", str(src_dir),
                 "--output-dir", str(out_dir),
                 "--max-batch-size", "10",
                 "--target-lang", "solidity",
                 "--json"],
                capture_output=True, text=True, timeout=30,
            )
            self.assertEqual(res.returncode, 0, msg=res.stderr)
            data = json.loads(res.stdout)
            self.assertEqual(data["records_emitted"], 3)


if __name__ == "__main__":
    unittest.main()
