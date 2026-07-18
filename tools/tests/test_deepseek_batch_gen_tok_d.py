"""Tests for tools/deepseek-batch-gen-tok-d.py.

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
TOOL = ROOT / "tools" / "deepseek-batch-gen-tok-d.py"


def _load_module():
    spec = importlib.util.spec_from_file_location("ds_batch_gen_tok_d", TOOL)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


M = _load_module()


SAMPLE_FRAME = """schema: auditooor.attacker_mental_frame.v1
frame_id: AMF-TEST-001
title: Test Frame Title
version: 1
status: active
bug_class: missing_validation
protocol_class:
  - bridge
  - lending
attacker_question: |
  Function A enforces guard G on resource R.
  Where else is R mutated without G?
preconditions:
  - "Caller has guard G"
  - "Resource R has multiple writers"
mental_steps:
  - id: 1
    do: "Identify G"
"""


SAMPLE_FRAME_MINIMAL = """schema: auditooor.attacker_mental_frame.v1
frame_id: AMF-MIN-002
title: Minimal frame
bug_class: reentrancy
"""


class TestYamlExtract(unittest.TestCase):
    def test_extracts_top_level_keys(self):
        out = M._minimal_yaml_extract(SAMPLE_FRAME)
        self.assertEqual(out.get("frame_id"), "AMF-TEST-001")
        self.assertEqual(out.get("title"), "Test Frame Title")
        self.assertEqual(out.get("bug_class"), "missing_validation")

    def test_extracts_list_protocol_class(self):
        out = M._minimal_yaml_extract(SAMPLE_FRAME)
        self.assertIn("bridge", out.get("protocol_class", []))
        self.assertIn("lending", out.get("protocol_class", []))

    def test_extracts_block_scalar_attacker_question(self):
        out = M._minimal_yaml_extract(SAMPLE_FRAME)
        aq = out.get("attacker_question", "")
        self.assertIn("Function A enforces guard G", aq)


class TestLoadAttackerFrames(unittest.TestCase):
    def test_loads_yaml(self):
        with tempfile.TemporaryDirectory() as td:
            p = Path(td) / "frame.yaml"
            p.write_text(SAMPLE_FRAME)
            frames = M.load_attacker_frames(p)
            self.assertEqual(len(frames), 1)
            self.assertEqual(frames[0]["frame_id"], "AMF-TEST-001")

    def test_returns_empty_on_empty_file(self):
        with tempfile.TemporaryDirectory() as td:
            p = Path(td) / "empty.yaml"
            p.write_text("")
            frames = M.load_attacker_frames(p)
            self.assertEqual(frames, [])


class TestBuildTaskRecord(unittest.TestCase):
    def test_record_shape(self):
        frame = {
            "frame_id": "AMF-TEST-001",
            "title": "Test Title",
            "bug_class": "missing_validation",
            "protocol_class": ["bridge"],
            "attacker_question": "Some question?",
            "preconditions": ["X", "Y"],
            "_source_path": "/fake.yaml",
        }
        rec = M.build_task_record(
            idx=3, frame=frame, task_id_prefix="tok_d_adversarial_persona",
            verification_tier="tier-3-synthetic-taxonomy-anchored",
            max_input_tokens=6000, max_output_tokens=2000,
        )
        self.assertEqual(rec["task_id"], "tok_d_adversarial_persona_0003")
        self.assertEqual(rec["task_type"], "tok_d_adversarial_persona")
        self.assertIn("AMF-TEST-001", rec["prompt"])
        self.assertIn("Some question", rec["prompt"])


class TestDryRun(unittest.TestCase):
    def test_dry_run_no_file(self):
        with tempfile.TemporaryDirectory() as td:
            src_dir = Path(td) / "frames"
            src_dir.mkdir()
            (src_dir / "f1.yaml").write_text(SAMPLE_FRAME)
            (src_dir / "f2.yaml").write_text(SAMPLE_FRAME_MINIMAL)
            out_dir = Path(td) / "out"
            res = subprocess.run(
                [sys.executable, str(TOOL),
                 "--source", str(src_dir),
                 "--output-dir", str(out_dir),
                 "--dry-run", "--json"],
                capture_output=True, text=True, timeout=30,
            )
            self.assertEqual(res.returncode, 0, msg=res.stderr)
            data = json.loads(res.stdout)
            self.assertEqual(data["status"], "dry-run")
            self.assertEqual(data["records_emitted"], 2)
            self.assertFalse(out_dir.exists())


class TestSmallBatchWrites(unittest.TestCase):
    def test_small_batch(self):
        with tempfile.TemporaryDirectory() as td:
            src_dir = Path(td) / "frames"
            src_dir.mkdir()
            (src_dir / "f1.yaml").write_text(SAMPLE_FRAME)
            out_dir = Path(td) / "out"
            res = subprocess.run(
                [sys.executable, str(TOOL),
                 "--source", str(src_dir),
                 "--output-dir", str(out_dir),
                 "--json"],
                capture_output=True, text=True, timeout=30,
            )
            self.assertEqual(res.returncode, 0, msg=res.stderr)
            data = json.loads(res.stdout)
            self.assertEqual(data["records_emitted"], 1)


class TestSchemaValidation(unittest.TestCase):
    def test_emitted_shape(self):
        with tempfile.TemporaryDirectory() as td:
            src_dir = Path(td) / "frames"
            src_dir.mkdir()
            (src_dir / "f.yaml").write_text(SAMPLE_FRAME)
            out_dir = Path(td) / "out"
            res = subprocess.run(
                [sys.executable, str(TOOL),
                 "--source", str(src_dir),
                 "--output-dir", str(out_dir),
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
    def test_frame_id_propagates(self):
        with tempfile.TemporaryDirectory() as td:
            src_dir = Path(td) / "frames"
            src_dir.mkdir()
            (src_dir / "f.yaml").write_text(SAMPLE_FRAME)
            out_dir = Path(td) / "out"
            res = subprocess.run(
                [sys.executable, str(TOOL),
                 "--source", str(src_dir),
                 "--output-dir", str(out_dir),
                 "--json"],
                capture_output=True, text=True, timeout=30,
            )
            data = json.loads(res.stdout)
            rec = json.loads(Path(data["output_path"]).read_text().strip().split("\n")[0])
            self.assertIn("AMF-TEST-001", rec["prompt"])
            self.assertIn("bridge", rec["prompt"])


if __name__ == "__main__":
    unittest.main()
