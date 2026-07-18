#!/usr/bin/env python3
# R36 pathspec discipline: lane-YAML-TO-MD-SLICE-BRIDGE registered in
# .auditooor/agent_pathspec.json (TTL 2h, registered 2026-05-26).
# <!-- r36-rebuttal: lane-YAML-TO-MD-SLICE-BRIDGE registered TTL 2h with this test file declared in pathspec -->

"""Tests for tools/yaml-corpus-to-md-slice.py.

Covers:
- Basic 3-record conversion -> expected bullet shape.
- Missing-field fallback (defaults to L severity, skipped if no handle/desc).
- Description truncation at --description-max-chars.
- Skip records with empty / whitespace-only description.
- Nested (dotted) field lookup for description (rekt-style).
- FINDING_LINE_RE compatibility with deepseek-batch-gen-tok-a.py.
- L34 refuse output path inside submissions/<status>/<slug>/.
- YAML parse-error tolerance (logged + skipped).
- Severity normalisation (critical/high -> H, medium -> M, info/unspecified -> L).
- Handle deduplication of `**` (would break bold delimiters).
- CLI smoke test end-to-end.
"""
from __future__ import annotations

import importlib.util
import json
import pathlib
import re
import subprocess
import sys
import tempfile
import unittest


REPO_ROOT = pathlib.Path(__file__).resolve().parents[2]
TOOL_PATH = REPO_ROOT / "tools" / "yaml-corpus-to-md-slice.py"
DEEPSEEK_PATH = REPO_ROOT / "tools" / "deepseek-batch-gen-tok-a.py"


def _load_tool():
    spec = importlib.util.spec_from_file_location("yaml_corpus_to_md_slice", TOOL_PATH)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


def _load_deepseek_finding_re():
    """Pull FINDING_LINE_RE from deepseek-batch-gen-tok-a.py for round-trip."""
    spec = importlib.util.spec_from_file_location("deepseek_batch_gen_tok_a", DEEPSEEK_PATH)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod.FINDING_LINE_RE


class YamlCorpusToMdSliceTests(unittest.TestCase):

    def setUp(self):
        self.tool = _load_tool()
        self.finding_re = _load_deepseek_finding_re()
        self.tmpdir = pathlib.Path(tempfile.mkdtemp(prefix="yaml_md_slice_"))

    def tearDown(self):
        import shutil
        shutil.rmtree(self.tmpdir, ignore_errors=True)

    def _write_record(self, slug: str, text: str, filename: str = "record.yaml") -> pathlib.Path:
        d = self.tmpdir / slug
        d.mkdir(parents=True, exist_ok=True)
        f = d / filename
        f.write_text(text, encoding="utf-8")
        return f

    # ---------- Basic conversion ----------

    def test_three_record_conversion(self):
        self._write_record("rec-001", (
            "record_id: corpus:rec-001\n"
            "severity: critical\n"
            "attack_vector_summary: 'Attacker drains pool via reentrancy.'\n"
        ))
        self._write_record("rec-002", (
            "record_id: corpus:rec-002\n"
            "severity: medium\n"
            "attack_vector_summary: 'Oracle returns stale price.'\n"
        ))
        self._write_record("rec-003", (
            "record_id: corpus:rec-003\n"
            "severity: info\n"
            "attack_vector_summary: 'Event omission.'\n"
        ))
        files = self.tool.find_yaml_files(self.tmpdir)
        bullets, stats = self.tool.convert_records(
            files,
            handle_field="record_id",
            severity_field="severity",
            description_field="attack_vector_summary",
            description_max_chars=400,
        )
        self.assertEqual(stats["files_seen"], 3)
        self.assertEqual(stats["emitted"], 3)
        self.assertEqual(stats["parse_errors"], 0)
        self.assertIn("- **corpus:rec-001** (H) - Attacker drains pool via reentrancy.", bullets)
        self.assertIn("- **corpus:rec-002** (M) - Oracle returns stale price.", bullets)
        self.assertIn("- **corpus:rec-003** (L) - Event omission.", bullets)

    # ---------- Missing-field handling ----------

    def test_missing_handle_skipped(self):
        self._write_record("rec-001", (
            "severity: high\n"
            "attack_vector_summary: 'desc'\n"
            # No record_id field
        ))
        files = self.tool.find_yaml_files(self.tmpdir)
        bullets, stats = self.tool.convert_records(
            files, "record_id", "severity", "attack_vector_summary", 400
        )
        self.assertEqual(stats["skipped_missing_handle"], 1)
        self.assertEqual(stats["emitted"], 0)
        self.assertEqual(bullets, [])

    def test_missing_severity_defaults_to_L(self):
        self._write_record("rec-001", (
            "record_id: corpus:rec-001\n"
            "attack_vector_summary: 'desc'\n"
        ))
        files = self.tool.find_yaml_files(self.tmpdir)
        bullets, stats = self.tool.convert_records(
            files, "record_id", "severity", "attack_vector_summary", 400
        )
        self.assertEqual(stats["emitted"], 1)
        self.assertEqual(bullets[0], "- **corpus:rec-001** (L) - desc")

    # ---------- Description truncation ----------

    def test_description_truncation(self):
        long_desc = "x" * 800
        self._write_record("rec-001", (
            f"record_id: corpus:rec-001\nseverity: high\nattack_vector_summary: '{long_desc}'\n"
        ))
        files = self.tool.find_yaml_files(self.tmpdir)
        bullets, stats = self.tool.convert_records(
            files, "record_id", "severity", "attack_vector_summary", 200
        )
        self.assertEqual(stats["emitted"], 1)
        bullet = bullets[0]
        self.assertTrue(bullet.endswith("..."), bullet)
        body_match = re.search(r" - (.+)\.\.\.$", bullet)
        self.assertIsNotNone(body_match)
        self.assertLessEqual(len(body_match.group(1)), 200)

    # ---------- Skip empty / whitespace description ----------

    def test_skip_empty_description(self):
        self._write_record("rec-001", (
            "record_id: corpus:rec-001\nseverity: high\nattack_vector_summary: ''\n"
        ))
        self._write_record("rec-002", (
            "record_id: corpus:rec-002\nseverity: high\nattack_vector_summary: '   '\n"
        ))
        files = self.tool.find_yaml_files(self.tmpdir)
        bullets, stats = self.tool.convert_records(
            files, "record_id", "severity", "attack_vector_summary", 400
        )
        self.assertEqual(stats["skipped_empty_desc"], 2)
        self.assertEqual(stats["emitted"], 0)

    # ---------- Nested / dotted field ----------

    def test_nested_dotted_field_lookup(self):
        self._write_record("rek-001", (
            "record_id: rek:001\n"
            "severity_at_finding: critical\n"
            "record_extensions:\n"
            "  attack_vector_summary: Bridge replay drains custody.\n"
        ))
        files = self.tool.find_yaml_files(self.tmpdir)
        bullets, stats = self.tool.convert_records(
            files,
            handle_field="record_id",
            severity_field="severity_at_finding",
            description_field="record_extensions.attack_vector_summary",
            description_max_chars=400,
        )
        self.assertEqual(stats["emitted"], 1)
        self.assertEqual(bullets[0], "- **rek:001** (H) - Bridge replay drains custody.")

    # ---------- FINDING_LINE_RE round-trip ----------

    def test_finding_line_re_round_trip(self):
        """Every emitted bullet must match deepseek-batch-gen-tok-a.py's FINDING_LINE_RE."""
        self._write_record("rec-001", (
            "record_id: corpus:rec-001\nseverity: critical\nattack_vector_summary: 'Drain.'\n"
        ))
        self._write_record("rec-002", (
            "record_id: corpus:rec-002\nseverity: medium\nattack_vector_summary: 'Stale price.'\n"
        ))
        files = self.tool.find_yaml_files(self.tmpdir)
        bullets, stats = self.tool.convert_records(
            files, "record_id", "severity", "attack_vector_summary", 400
        )
        for b in bullets:
            m = self.finding_re.match(b)
            self.assertIsNotNone(m, f"FINDING_LINE_RE did not match: {b!r}")

    # ---------- L34 refusal ----------

    def test_l34_refuses_submissions_per_finding_folder(self):
        bad_path = self.tmpdir / "submissions" / "filed" / "my-slug" / "my-slug.md"
        self.assertTrue(self.tool._l34_refuses_output(bad_path))
        ok_path = self.tmpdir / "submissions" / "SUBMISSIONS.md"
        self.assertFalse(self.tool._l34_refuses_output(ok_path))
        ok2 = self.tmpdir / "reference" / "corpus_mined" / "foo.md"
        self.assertFalse(self.tool._l34_refuses_output(ok2))

    # ---------- Parse error tolerance ----------

    def test_unreadable_yaml_does_not_crash(self):
        broken = self.tmpdir / "broken" / "record.yaml"
        broken.parent.mkdir(parents=True)
        broken.write_text("this is not a yaml mapping at all just text\n", encoding="utf-8")
        files = self.tool.find_yaml_files(self.tmpdir)
        bullets, stats = self.tool.convert_records(
            files, "record_id", "severity", "attack_vector_summary", 400
        )
        self.assertEqual(stats["emitted"], 0)

    # ---------- Severity normalisation ----------

    def test_severity_normalisation_matrix(self):
        cases = [
            ("critical", "H"),
            ("high", "H"),
            ("medium", "M"),
            ("info", "L"),
            ("unspecified", "L"),
            ("unknown", "L"),
            ("", "L"),
            (None, "L"),
            ("LOW", "L"),
        ]
        for raw, expected in cases:
            self.assertEqual(self.tool.normalise_severity(raw), expected, f"sev={raw!r}")

    # ---------- Handle deduplication of `**` ----------

    def test_handle_strips_bold_delimiters(self):
        self._write_record("rec-001", (
            "record_id: 'corpus:**rec**:001'\n"
            "severity: high\n"
            "attack_vector_summary: 'desc'\n"
        ))
        files = self.tool.find_yaml_files(self.tmpdir)
        bullets, stats = self.tool.convert_records(
            files, "record_id", "severity", "attack_vector_summary", 400
        )
        self.assertEqual(stats["emitted"], 1)
        self.assertEqual(bullets[0], "- **corpus:rec:001** (H) - desc")

    # ---------- Multi-line quoted scalar (darknavy/rekt style) ----------
    # <!-- r36-rebuttal: lane-YAML-TO-MD-SLICE-BRIDGE registered TTL 2h -->

    def test_wrapped_single_quoted_scalar(self):
        """Single-quoted value that wraps across multiple indented lines."""
        self._write_record("rec-001", (
            "record_id: corpus:rec-001\n"
            "severity: critical\n"
            "attacker_action_sequence: 'Attacker exploits via reentrancy on\n"
            "  callback path; loops back into vault mint() before state\n"
            "  update, doubling shares; total loss ~1200 ETH.'\n"
        ))
        files = self.tool.find_yaml_files(self.tmpdir)
        bullets, stats = self.tool.convert_records(
            files, "record_id", "severity", "attacker_action_sequence", 600
        )
        self.assertEqual(stats["emitted"], 1)
        self.assertIn("Attacker exploits via reentrancy", bullets[0])
        self.assertIn("doubling shares", bullets[0])

    def test_plain_scalar_folded_continuation(self):
        """Unquoted plain scalar wrapped on next indented line."""
        self._write_record("rec-001", (
            "record_id: corpus:rec-001\n"
            "severity: high\n"
            "attack_vector_summary: Bridge replay drains user custody\n"
            "    when the consume-once gate is absent on settlement path.\n"
            "title: Something Else\n"
        ))
        files = self.tool.find_yaml_files(self.tmpdir)
        bullets, stats = self.tool.convert_records(
            files, "record_id", "severity", "attack_vector_summary", 400
        )
        self.assertEqual(stats["emitted"], 1)
        self.assertIn("consume-once gate is absent", bullets[0])

    # ---------- CLI smoke test ----------

    def test_cli_smoke_end_to_end(self):
        self._write_record("rec-001", (
            "record_id: corpus:rec-001\nseverity: critical\nattack_vector_summary: 'Drain.'\n"
        ))
        self._write_record("rec-002", (
            "record_id: corpus:rec-002\nseverity: medium\nattack_vector_summary: 'Stale price.'\n"
        ))
        out_path = self.tmpdir / "out.md"
        result = subprocess.run(
            [
                sys.executable,
                str(TOOL_PATH),
                "--input-dir", str(self.tmpdir),
                "--output", str(out_path),
                "--handle-field", "record_id",
                "--severity-field", "severity",
                "--description-field", "attack_vector_summary",
                "--json",
            ],
            capture_output=True,
            text=True,
            check=False,
        )
        self.assertEqual(result.returncode, 0, f"stderr={result.stderr}")
        self.assertTrue(out_path.exists())
        summary = json.loads(result.stdout)
        self.assertEqual(summary["stats"]["emitted"], 2)
        body = out_path.read_text(encoding="utf-8")
        self.assertIn("- **corpus:rec-001** (H) - Drain.", body)
        self.assertIn("- **corpus:rec-002** (M) - Stale price.", body)
        bullet_lines = [ln for ln in body.splitlines() if ln.startswith("- **")]
        for bln in bullet_lines:
            self.assertIsNotNone(self.finding_re.match(bln), f"line failed: {bln}")


if __name__ == "__main__":
    unittest.main()
