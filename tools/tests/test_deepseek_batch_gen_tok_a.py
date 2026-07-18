"""Tests for tools/deepseek-batch-gen-tok-a.py.

All inputs mocked via tmpdir. NEVER touches network or real corpus dirs.

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
TOOL = ROOT / "tools" / "deepseek-batch-gen-tok-a.py"


def _load_module():
    spec = importlib.util.spec_from_file_location("ds_batch_gen_tok_a", TOOL)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


M = _load_module()


SAMPLE_SLICE = """# Sample slice
## Findings

### 2024-07-foo - Foo Protocol
- **bar-missing-slippage** (H) - swap function has no slippage check. Detection: DETECTOR. Novel: YES.
- **baz-reentrancy-cross-fn** (M) - callback into withdraw enables drain. Detection: DETECTOR. Novel: NO.
- **qux-oracle-stale** (H) - no heartbeat check on oracle reads. Detection: DETECTOR. Novel: UNKNOWN.

### 2024-08-foo2 - Foo2 Protocol
- **frobnitz-misordered-update** (M) - state update after external call. Detection: DOCS. Novel: NO.
"""


class TestExtractFindings(unittest.TestCase):
    def test_extracts_all_four(self):
        findings = M.extract_findings(SAMPLE_SLICE, "/fake/path.md")
        self.assertEqual(len(findings), 4)
        handles = [f["finding_handle"] for f in findings]
        self.assertIn("bar-missing-slippage", handles)
        self.assertIn("frobnitz-misordered-update", handles)
        # Each finding carries severity.
        self.assertEqual(findings[0]["severity"], "H")
        self.assertEqual(findings[3]["severity"], "M")

    def test_handles_empty_text(self):
        self.assertEqual(M.extract_findings("", "/fake.md"), [])

    def test_skips_non_finding_lines(self):
        text = "## Just a heading\n\nSome prose with no findings.\n\n- not a finding bullet"
        self.assertEqual(M.extract_findings(text, "/fake.md"), [])


class TestBuildTaskRecord(unittest.TestCase):
    def test_record_shape(self):
        finding = {
            "finding_handle": "test-handle",
            "severity": "H",
            "desc": "test desc",
            "finding_line": "test-handle (H) - test desc",
            "source_path": "/fake.md",
        }
        rec = M.build_task_record(
            idx=42, finding=finding, task_id_prefix="tok_a_rationale_mine",
            verification_tier="tier-3-synthetic-taxonomy-anchored",
            max_input_tokens=6000, max_output_tokens=1500,
        )
        # Required dispatcher-contract fields.
        self.assertEqual(rec["task_id"], "tok_a_rationale_mine_0042")
        self.assertEqual(rec["task_type"], "tok_a_rationale_mine")
        self.assertIn("prompt", rec)
        self.assertIn("test-handle", rec["prompt"])
        self.assertEqual(rec["max_input_tokens"], 6000)
        self.assertEqual(rec["max_output_tokens"], 1500)
        self.assertEqual(rec["verification_tier_target"], "tier-3-synthetic-taxonomy-anchored")
        # Meta.
        self.assertEqual(rec["meta"]["finding_handle"], "test-handle")
        self.assertEqual(rec["meta"]["generator"], "deepseek-batch-gen-tok-a")
        self.assertEqual(rec["meta"]["schema_id"], "auditooor.deepseek_batch_gen_tok_a.v1")


class TestDryRun(unittest.TestCase):
    def test_dry_run_prints_summary_no_file_written(self):
        with tempfile.TemporaryDirectory() as td:
            src = Path(td) / "src.md"
            src.write_text(SAMPLE_SLICE)
            out_dir = Path(td) / "out"
            res = subprocess.run(
                [sys.executable, str(TOOL),
                 "--source", str(src),
                 "--output-dir", str(out_dir),
                 "--max-batch-size", "3",
                 "--dry-run", "--json"],
                capture_output=True, text=True, timeout=30,
            )
            self.assertEqual(res.returncode, 0, msg=res.stderr)
            data = json.loads(res.stdout)
            self.assertEqual(data["status"], "dry-run")
            self.assertEqual(data["records_emitted"], 3)
            self.assertIsNone(data["output_path"])
            self.assertFalse(out_dir.exists(), "dry-run must not create output dir")


class TestSmallBatchWritesCorrectly(unittest.TestCase):
    def test_small_batch_writes_jsonl(self):
        with tempfile.TemporaryDirectory() as td:
            src = Path(td) / "src.md"
            src.write_text(SAMPLE_SLICE)
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
            self.assertEqual(data["status"], "ok")
            self.assertEqual(data["records_emitted"], 3)
            out_path = Path(data["output_path"])
            self.assertTrue(out_path.exists())
            # Each line is valid JSON with required shape.
            lines = out_path.read_text(encoding="utf-8").strip().split("\n")
            self.assertEqual(len(lines), 3)
            for ln in lines:
                rec = json.loads(ln)
                for key in ("task_id", "task_type", "prompt",
                            "max_input_tokens", "max_output_tokens",
                            "verification_tier_target", "meta"):
                    self.assertIn(key, rec)

    def test_skip_existing_resumes_after_max_existing_id(self):
        with tempfile.TemporaryDirectory() as td:
            src_dir = Path(td) / "slices"
            src_dir.mkdir()
            (src_dir / "a.md").write_text(SAMPLE_SLICE)
            (src_dir / "b.md").write_text(SAMPLE_SLICE)
            done_dir = Path(td) / "done"
            done_dir.mkdir()
            (done_dir / "solodit_med_tok_a_0003.json").write_text("{}\n")
            (done_dir / "solodit_med_tok_a_0005.json").write_text("{}\n")
            out_dir = Path(td) / "out"
            res = subprocess.run(
                [sys.executable, str(TOOL),
                 "--source", str(src_dir),
                 "--output-dir", str(out_dir),
                 "--max-batch-size", "2",
                 "--task-id-prefix", "solodit_med_tok_a",
                 "--skip-existing-in-dir", str(done_dir),
                 "--json"],
                capture_output=True, text=True, timeout=30,
            )
            self.assertEqual(res.returncode, 0, msg=res.stderr)
            data = json.loads(res.stdout)
            self.assertEqual(data["records_emitted"], 2)
            self.assertEqual(data["existing_task_count"], 2)
            self.assertEqual(data["max_existing_task_index"], 5)
            self.assertEqual(
                data["sample_task_ids"],
                ["solodit_med_tok_a_0006", "solodit_med_tok_a_0007"],
            )
            out_path = Path(data["output_path"])
            lines = out_path.read_text(encoding="utf-8").strip().split("\n")
            task_ids = [json.loads(line)["task_id"] for line in lines]
            self.assertEqual(
                task_ids,
                ["solodit_med_tok_a_0006", "solodit_med_tok_a_0007"],
            )


class TestSchemaValidationOfEmittedJSONL(unittest.TestCase):
    def test_emitted_records_match_dispatcher_contract(self):
        with tempfile.TemporaryDirectory() as td:
            src = Path(td) / "src.md"
            src.write_text(SAMPLE_SLICE)
            out_dir = Path(td) / "out"
            res = subprocess.run(
                [sys.executable, str(TOOL),
                 "--source", str(src),
                 "--output-dir", str(out_dir),
                 "--max-batch-size", "10",
                 "--json"],
                capture_output=True, text=True, timeout=30,
            )
            self.assertEqual(res.returncode, 0, msg=res.stderr)
            data = json.loads(res.stdout)
            out_path = Path(data["output_path"])
            lines = out_path.read_text(encoding="utf-8").strip().split("\n")
            for ln in lines:
                rec = json.loads(ln)
                self.assertIsInstance(rec["task_id"], str)
                self.assertEqual(rec["task_type"], "tok_a_rationale_mine")
                self.assertIsInstance(rec["prompt"], str)
                self.assertGreater(len(rec["prompt"]), 50)
                self.assertEqual(rec["verification_tier_target"],
                                 "tier-3-synthetic-taxonomy-anchored")
                self.assertIsInstance(rec["meta"], dict)


class TestPromptTemplateInsertion(unittest.TestCase):
    def test_finding_line_inserted_into_prompt(self):
        finding = {
            "finding_handle": "unique-token-marker-XYZ",
            "severity": "H",
            "desc": "distinctive description xyz",
            "finding_line": "unique-token-marker-XYZ (H) - distinctive description xyz",
            "source_path": "/some/path.md",
        }
        rec = M.build_task_record(
            idx=1, finding=finding, task_id_prefix="tok_a_rationale_mine",
            verification_tier="tier-3-synthetic-taxonomy-anchored",
            max_input_tokens=6000, max_output_tokens=1500,
        )
        self.assertIn("unique-token-marker-XYZ", rec["prompt"])
        self.assertIn("distinctive description xyz", rec["prompt"])
        self.assertIn("/some/path.md", rec["prompt"])


class TestEndToEndWithMockSource(unittest.TestCase):
    def test_e2e_directory_source(self):
        with tempfile.TemporaryDirectory() as td:
            src_dir = Path(td) / "slices"
            src_dir.mkdir()
            (src_dir / "a.md").write_text(SAMPLE_SLICE)
            (src_dir / "b.md").write_text(SAMPLE_SLICE)
            out_dir = Path(td) / "out"
            res = subprocess.run(
                [sys.executable, str(TOOL),
                 "--source", str(src_dir),
                 "--output-dir", str(out_dir),
                 "--max-batch-size", "10",
                 "--json"],
                capture_output=True, text=True, timeout=30,
            )
            self.assertEqual(res.returncode, 0, msg=res.stderr)
            data = json.loads(res.stdout)
            # 4 findings per file * 2 files = 8 emitted.
            self.assertEqual(data["records_emitted"], 8)


class TestL34Refusal(unittest.TestCase):
    def test_draft_file_path_refused(self):
        # Build a path that matches the L34 draft-file regex.
        p = Path("submissions/filed/some-slug/some-slug.md")
        self.assertTrue(M._l34_refuses_path(p))

    def test_safe_path_allowed(self):
        p = Path("audit/corpus_tags/derived/deepseek_fanout/tok-a/x.jsonl")
        self.assertFalse(M._l34_refuses_path(p))


if __name__ == "__main__":
    unittest.main()
