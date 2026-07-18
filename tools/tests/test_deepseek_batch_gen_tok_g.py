"""Tests for tools/deepseek-batch-gen-tok-g.py.

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
TOOL = ROOT / "tools" / "deepseek-batch-gen-tok-g.py"


def _load_module():
    spec = importlib.util.spec_from_file_location("ds_batch_gen_tok_g", TOOL)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


M = _load_module()


SAMPLE_ANTIPATTERNS = """# Test Anti-patterns

Some intro.

## Methodology anti-patterns

### 1. Skipping on-chain enumeration

**What happens:** Sample text 1.

**Why it's wrong:** Sample wrong text 1.

**Correction:** Sample correction 1.

---

### 2. Trusting agent output

**What happens:** Sample text 2.

**Why it's wrong:** Sample wrong text 2.

**Correction:** Sample correction 2.

---

### 3. Not tracking closures

**What happens:** Sample text 3.

**Correction:** Sample correction 3.

---

## Another section

### 4. Different category

**What happens:** Sample text 4.
"""


class TestExtractAntiPatterns(unittest.TestCase):
    def test_extracts_all_entries(self):
        entries = M.extract_anti_patterns(SAMPLE_ANTIPATTERNS, "/fake.md")
        # 4 entries (sections shouldn't break parsing since we only look at ###).
        self.assertEqual(len(entries), 4)
        titles = [e["title"] for e in entries]
        self.assertIn("Skipping on-chain enumeration", titles)
        self.assertIn("Different category", titles)

    def test_body_captured(self):
        entries = M.extract_anti_patterns(SAMPLE_ANTIPATTERNS, "/fake.md")
        self.assertIn("Sample text 1", entries[0]["body"])
        self.assertIn("Sample correction 1", entries[0]["body"])

    def test_empty_input(self):
        self.assertEqual(M.extract_anti_patterns("", "/fake.md"), [])


class TestBuildTaskRecord(unittest.TestCase):
    def test_record_shape(self):
        entry = {
            "title": "Test anti-pattern",
            "body": "Some body about the anti-pattern.",
            "source_path": "/fake.md",
        }
        rec = M.build_task_record(
            idx=5, entry=entry, task_id_prefix="tok_g_antipattern_expand",
            verification_tier="tier-3-synthetic-taxonomy-anchored",
            max_input_tokens=6000, max_output_tokens=2000,
        )
        self.assertEqual(rec["task_id"], "tok_g_antipattern_expand_0005")
        self.assertEqual(rec["task_type"], "tok_g_antipattern_expand")
        self.assertIn("Test anti-pattern", rec["prompt"])
        self.assertIn("Some body", rec["prompt"])


class TestDryRun(unittest.TestCase):
    def test_dry_run(self):
        with tempfile.TemporaryDirectory() as td:
            src = Path(td) / "ap.md"
            src.write_text(SAMPLE_ANTIPATTERNS)
            out_dir = Path(td) / "out"
            res = subprocess.run(
                [sys.executable, str(TOOL),
                 "--source", str(src),
                 "--output-dir", str(out_dir),
                 "--max-batch-size", "10",
                 "--dry-run", "--json"],
                capture_output=True, text=True, timeout=30,
            )
            self.assertEqual(res.returncode, 0, msg=res.stderr)
            data = json.loads(res.stdout)
            self.assertEqual(data["status"], "dry-run")
            self.assertEqual(data["records_emitted"], 4)
            self.assertFalse(out_dir.exists())


class TestSmallBatchWrites(unittest.TestCase):
    def test_small_batch(self):
        with tempfile.TemporaryDirectory() as td:
            src = Path(td) / "ap.md"
            src.write_text(SAMPLE_ANTIPATTERNS)
            out_dir = Path(td) / "out"
            res = subprocess.run(
                [sys.executable, str(TOOL),
                 "--source", str(src),
                 "--output-dir", str(out_dir),
                 "--max-batch-size", "3",
                 "--json"],
                capture_output=True, text=True, timeout=30,
            )
            self.assertEqual(res.returncode, 0, msg=res.stderr)
            data = json.loads(res.stdout)
            self.assertEqual(data["records_emitted"], 3)
            out_path = Path(data["output_path"])
            self.assertTrue(out_path.exists())


class TestSchemaValidation(unittest.TestCase):
    def test_emitted_shape(self):
        with tempfile.TemporaryDirectory() as td:
            src = Path(td) / "ap.md"
            src.write_text(SAMPLE_ANTIPATTERNS)
            out_dir = Path(td) / "out"
            res = subprocess.run(
                [sys.executable, str(TOOL),
                 "--source", str(src),
                 "--output-dir", str(out_dir),
                 "--max-batch-size", "5",
                 "--json"],
                capture_output=True, text=True, timeout=30,
            )
            data = json.loads(res.stdout)
            for ln in Path(data["output_path"]).read_text().strip().split("\n"):
                rec = json.loads(ln)
                for k in ("task_id", "task_type", "prompt",
                          "max_input_tokens", "max_output_tokens",
                          "verification_tier_target", "meta"):
                    self.assertIn(k, rec)


class TestPromptTemplateInsertion(unittest.TestCase):
    def test_title_and_body_in_prompt(self):
        entry = {
            "title": "Unique-Marker-Title-XYZ",
            "body": "Unique-Marker-Body-ABC content",
            "source_path": "/fake.md",
        }
        rec = M.build_task_record(
            idx=1, entry=entry, task_id_prefix="tok_g_antipattern_expand",
            verification_tier="tier-3-synthetic-taxonomy-anchored",
            max_input_tokens=6000, max_output_tokens=2000,
        )
        self.assertIn("Unique-Marker-Title-XYZ", rec["prompt"])
        self.assertIn("Unique-Marker-Body-ABC", rec["prompt"])


if __name__ == "__main__":
    unittest.main()
