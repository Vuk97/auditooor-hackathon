"""Tests for tools/hackerman-apply-verification-tier.py.

Verifies that the apply tool:
  - Adds a `verification_tier:<tier>` tag inside `function_shape.shape_tags`.
  - Is idempotent (re-running does not duplicate).
  - Skips records that already carry a different tier tag, unless --force.
  - Preserves all other record fields byte-for-byte.
"""
from __future__ import annotations

import importlib.util
import json
import tempfile
import textwrap
import unittest
from pathlib import Path


REPO_ROOT = Path(__file__).resolve().parents[2]
TOOL_PATH = REPO_ROOT / "tools" / "hackerman-apply-verification-tier.py"


def _load_tool():
    spec = importlib.util.spec_from_file_location(
        "_hackerman_apply_verification_tier", str(TOOL_PATH)
    )
    mod = importlib.util.module_from_spec(spec)
    assert spec.loader
    spec.loader.exec_module(mod)
    return mod


SAMPLE_RECORD = """
schema_version: auditooor.hackerman_record.v1
record_id: prior-audit:foo:abc
source_audit_ref: prior-audit:foo:DIGEST.md
target_repo: owner/repo
target_language: solidity
target_component: SomeFunc
function_shape:
  raw_signature: function someFunc()
  shape_tags:
    - language:solidity
    - reentrancy
bug_class: x
attack_class: y
"""


class ApplyTierTextTests(unittest.TestCase):
    def setUp(self) -> None:
        self.tool = _load_tool()

    def test_adds_new_tag(self) -> None:
        new_text, status = self.tool.apply_tier_to_record_text(
            SAMPLE_RECORD, "tier-2-verified-public-archive"
        )
        self.assertEqual(status, "added")
        self.assertIn(
            "- verification_tier:tier-2-verified-public-archive", new_text
        )
        # Existing tags preserved
        self.assertIn("- language:solidity", new_text)
        self.assertIn("- reentrancy", new_text)
        # All other lines unchanged (count preserved + 1)
        self.assertEqual(
            len(new_text.splitlines()), len(SAMPLE_RECORD.splitlines()) + 1
        )

    def test_idempotent_noop(self) -> None:
        once, _ = self.tool.apply_tier_to_record_text(
            SAMPLE_RECORD, "tier-2-verified-public-archive"
        )
        twice, status = self.tool.apply_tier_to_record_text(
            once, "tier-2-verified-public-archive"
        )
        self.assertEqual(status, "noop")
        self.assertEqual(once, twice)

    def test_skips_when_different_tier_present_without_force(self) -> None:
        once, _ = self.tool.apply_tier_to_record_text(
            SAMPLE_RECORD, "tier-2-verified-public-archive"
        )
        result, status = self.tool.apply_tier_to_record_text(
            once, "tier-3-synthetic-taxonomy-anchored"
        )
        self.assertEqual(status, "skipped")
        # File text unchanged when skipped
        self.assertEqual(once, result)

    def test_force_replaces_existing(self) -> None:
        once, _ = self.tool.apply_tier_to_record_text(
            SAMPLE_RECORD, "tier-2-verified-public-archive"
        )
        result, status = self.tool.apply_tier_to_record_text(
            once, "tier-3-synthetic-taxonomy-anchored", force=True
        )
        self.assertEqual(status, "replaced")
        self.assertIn(
            "- verification_tier:tier-3-synthetic-taxonomy-anchored", result
        )
        self.assertNotIn(
            "- verification_tier:tier-2-verified-public-archive", result
        )

    def test_no_shape_when_block_missing(self) -> None:
        broken = """
            schema_version: auditooor.hackerman_record.v1
            record_id: x:y
            source_audit_ref: x
            """
        new_text, status = self.tool.apply_tier_to_record_text(
            textwrap.dedent(broken).lstrip(), "tier-3-synthetic-taxonomy-anchored"
        )
        self.assertEqual(status, "no-shape")
        # No-op
        self.assertEqual(new_text, textwrap.dedent(broken).lstrip())

    def test_handles_same_indent_list_items(self) -> None:
        # Legacy hackerman writer emits shape_tags items at the SAME indent
        # level as the `shape_tags:` header (not nested deeper). The parser
        # must accept this YAML-legal layout.
        same_indent_record = (
            "schema_version: auditooor.hackerman_record.v1\n"
            "record_id: legacy:foo:abc\n"
            "source_audit_ref: foo\n"
            "function_shape:\n"
            "  raw_signature: func ()\n"
            "  shape_tags:\n"
            "  - hash1\n"
            "  - hash2\n"
            "bug_class: x\n"
        )
        new_text, status = self.tool.apply_tier_to_record_text(
            same_indent_record, "tier-2-verified-public-archive"
        )
        self.assertEqual(status, "added")
        self.assertIn(
            "- verification_tier:tier-2-verified-public-archive", new_text
        )
        # Existing tags preserved
        self.assertIn("- hash1", new_text)
        self.assertIn("- hash2", new_text)
        # bug_class line still present, no spurious indent
        self.assertIn("bug_class: x", new_text)

    def test_preserves_other_fields_bytewise(self) -> None:
        new_text, _ = self.tool.apply_tier_to_record_text(
            SAMPLE_RECORD, "tier-1-verified-realtime-api"
        )
        # Every original line still present.
        for line in SAMPLE_RECORD.splitlines():
            self.assertIn(line, new_text.splitlines())


class ApplyIntegrationTests(unittest.TestCase):
    def setUp(self) -> None:
        self.tool = _load_tool()
        self.tmp = tempfile.TemporaryDirectory()
        root = Path(self.tmp.name)
        self.tags_dir = root / "audit" / "corpus_tags" / "tags"
        self.tags_dir.mkdir(parents=True)
        self.candidates_path = root / ".auditooor" / "candidates.jsonl"
        self.candidates_path.parent.mkdir(parents=True)

    def tearDown(self) -> None:
        self.tmp.cleanup()

    def _write_record(self, name: str, body: str) -> Path:
        p = self.tags_dir / name
        p.write_text(textwrap.dedent(body).lstrip(), encoding="utf-8")
        return p

    def _write_candidates(self, entries) -> None:
        with self.candidates_path.open("w", encoding="utf-8") as fh:
            for e in entries:
                fh.write(json.dumps(e) + "\n")

    def test_apply_uses_repo_relative_file_field(self) -> None:
        record = self._write_record("rec.yaml", SAMPLE_RECORD)
        self._write_candidates(
            [
                {
                    "record_id": "prior-audit:foo:abc",
                    "file": "audit/corpus_tags/tags/rec.yaml",
                    "verification_tier": "tier-2-verified-public-archive",
                    "reason": "tier2-prefix:prior-audit:",
                }
            ]
        )
        summary = self.tool.apply(
            self.candidates_path, self.tags_dir, apply_changes=True
        )
        self.assertEqual(summary.get("added", 0), 1)
        text = record.read_text(encoding="utf-8")
        self.assertIn("verification_tier:tier-2-verified-public-archive", text)

    def test_dry_run_does_not_modify_files(self) -> None:
        record = self._write_record("rec.yaml", SAMPLE_RECORD)
        original = record.read_text(encoding="utf-8")
        self._write_candidates(
            [
                {
                    "record_id": "prior-audit:foo:abc",
                    "file": "audit/corpus_tags/tags/rec.yaml",
                    "verification_tier": "tier-2-verified-public-archive",
                    "reason": "tier2-prefix:prior-audit:",
                }
            ]
        )
        self.tool.apply(
            self.candidates_path, self.tags_dir, apply_changes=False
        )
        self.assertEqual(record.read_text(encoding="utf-8"), original)

    def test_missing_record_file_counted(self) -> None:
        self._write_candidates(
            [
                {
                    "record_id": "ghost:foo",
                    "file": "audit/corpus_tags/tags/does-not-exist.yaml",
                    "verification_tier": "tier-3-synthetic-taxonomy-anchored",
                    "reason": "x",
                }
            ]
        )
        summary = self.tool.apply(
            self.candidates_path, self.tags_dir, apply_changes=True
        )
        self.assertEqual(summary.get("missing", 0), 1)


if __name__ == "__main__":
    unittest.main()
