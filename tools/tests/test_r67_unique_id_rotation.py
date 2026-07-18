# r36-rebuttal: work3-r67-unique-id-2026-05-26 registered in .auditooor/agent_pathspec.json via tools/agent-pathspec-register.py register
"""Regression tests for R67 unique-record-ID rotation_log schema extension.

Task #229 forensic anchor: the LIFT-19 "940 audited records" figure was an
overcount artifact. Line-count inflation from ~50% intra-file duplication
caused the shrinkage detector to misclassify dedup as data loss. These tests
verify the new unique_record_id_count_before/after + dedup_dropped_count
fields distinguish real loss from dedup compaction.

Run:
    cd /Users/wolf/auditooor-mcp
    python3 -m pytest tools/tests/test_r67_unique_id_rotation.py -v
or:
    python3 -m unittest tools.tests.test_r67_unique_id_rotation -v
"""
from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path

import importlib.util
import sys

_REPO = Path(__file__).resolve().parent.parent.parent
sys.path.insert(0, str(_REPO))

from tools.lib.atomic_corpus_writer import (  # noqa: E402
    DEFAULT_ID_FIELDS,
    _count_unique_record_ids,
    atomic_write_corpus_file,
    read_rotation_log,
)

# The verifier module uses hyphens in its filename so use importlib.
_VERIFIER_PATH = _REPO / "tools" / "r67-rotation-cursor-verifier.py"
_spec = importlib.util.spec_from_file_location("r67_rotation_cursor_verifier", _VERIFIER_PATH)
_mod = importlib.util.module_from_spec(_spec)
sys.modules["r67_rotation_cursor_verifier"] = _mod
_spec.loader.exec_module(_mod)
verify_file = _mod.verify_file


def _make_jsonl(records: list[dict]) -> bytes:
    return b"\n".join(json.dumps(r).encode() for r in records) + b"\n"


class TestCountUniqueRecordIds(unittest.TestCase):
    """Unit tests for _count_unique_record_ids helper."""

    def test_default_field_invariant_id(self):
        records = [{"invariant_id": f"INV-{i}", "data": "x"} for i in range(50)]
        data = _make_jsonl(records)
        count, field = _count_unique_record_ids(data)
        self.assertEqual(count, 50)
        self.assertEqual(field, "invariant_id")

    def test_default_field_record_id_first_priority(self):
        records = [{"record_id": f"REC-{i}", "invariant_id": f"INV-{i}"} for i in range(30)]
        data = _make_jsonl(records)
        count, field = _count_unique_record_ids(data)
        self.assertEqual(count, 30)
        self.assertEqual(field, "record_id")  # record_id is first in DEFAULT_ID_FIELDS

    def test_100_lines_50_unique_ids(self):
        """100 lines with 50% duplication -> unique count 50, dedup_dropped 50."""
        records = [{"invariant_id": f"INV-{i % 50}", "payload": f"v{i}"} for i in range(100)]
        data = _make_jsonl(records)
        count, field = _count_unique_record_ids(data)
        self.assertEqual(count, 50)
        self.assertEqual(field, "invariant_id")

    def test_explicit_field_override(self):
        records = [{"gct_id": f"GCT-{i}", "other": "z"} for i in range(20)]
        data = _make_jsonl(records)
        count, field = _count_unique_record_ids(data, record_id_field="gct_id")
        self.assertEqual(count, 20)
        self.assertEqual(field, "gct_id")

    def test_no_recognized_id_field_returns_none(self):
        """JSONL with no recognized ID field -> (None, None)."""
        records = [{"foo": i, "bar": "baz"} for i in range(10)]
        data = _make_jsonl(records)
        count, field = _count_unique_record_ids(data)
        self.assertIsNone(count)
        self.assertIsNone(field)

    def test_empty_data_returns_none(self):
        count, field = _count_unique_record_ids(b"")
        self.assertIsNone(count)
        self.assertIsNone(field)

    def test_malformed_lines_skipped(self):
        data = b'{"invariant_id": "INV-1"}\nnot-json\n{"invariant_id": "INV-2"}\n'
        count, field = _count_unique_record_ids(data)
        self.assertEqual(count, 2)


class TestRotationLogUniqueIdFields(unittest.TestCase):
    """Integration tests: atomic_write_corpus_file emits correct uid fields."""

    def setUp(self):
        self._tmpdir = tempfile.TemporaryDirectory()
        self.tmp = Path(self._tmpdir.name)

    def tearDown(self):
        self._tmpdir.cleanup()

    def test_rotation_log_includes_uid_fields_on_overwrite(self):
        """Write 50 unique records, then overwrite with 100-line / 50-unique version."""
        corpus = self.tmp / "corpus.jsonl"
        # Initial write: 50 unique records
        v1 = _make_jsonl([{"invariant_id": f"INV-{i}", "v": 1} for i in range(50)])
        atomic_write_corpus_file(corpus, v1, prune=False)

        # Second write: 100 lines but only 50 unique IDs (dedup scenario)
        v2 = _make_jsonl([{"invariant_id": f"INV-{i % 50}", "v": 2} for i in range(100)])
        result = atomic_write_corpus_file(corpus, v2, prune=False)

        self.assertEqual(result["unique_record_id_count_before"], 50)
        self.assertEqual(result["unique_record_id_count_after"], 50)
        self.assertEqual(result["record_id_field"], "invariant_id")
        # dedup_dropped_count = line_count_before - uid_before = 50 - 50 = 0
        self.assertEqual(result["dedup_dropped_count"], 0)

        # Verify the rotation_log also has the new fields
        log = read_rotation_log(corpus)
        last = log[-1]
        self.assertEqual(last["unique_record_id_count_before"], 50)
        self.assertEqual(last["unique_record_id_count_after"], 50)
        self.assertEqual(last["record_id_field"], "invariant_id")

    def test_dedup_dropped_count_nonzero(self):
        """Initial file has 100 lines / 50 unique -> dedup_dropped=50."""
        corpus = self.tmp / "corpus2.jsonl"
        # Initial write (before=0 since file is new)
        v1 = _make_jsonl([{"invariant_id": f"INV-{i % 50}", "v": 1} for i in range(100)])
        result = atomic_write_corpus_file(corpus, v1, prune=False)
        # prior_data is empty b"", so uid_before = None; dedup_dropped = None
        self.assertIsNone(result["unique_record_id_count_before"])
        self.assertEqual(result["unique_record_id_count_after"], 50)

        # Overwrite with same 100-line/50-unique content: now before=50, after=50
        v2 = _make_jsonl([{"invariant_id": f"INV-{i % 50}", "v": 2} for i in range(100)])
        result2 = atomic_write_corpus_file(corpus, v2, prune=False)
        self.assertEqual(result2["unique_record_id_count_before"], 50)
        self.assertEqual(result2["unique_record_id_count_after"], 50)
        # line_count_before = 100, uid_before = 50 -> dedup_dropped = 50
        self.assertEqual(result2["dedup_dropped_count"], 50)

    def test_no_recognized_id_field_emits_null(self):
        """JSONL with no recognized ID field -> uid fields are None."""
        corpus = self.tmp / "corpus3.jsonl"
        v1 = _make_jsonl([{"foo": i} for i in range(10)])
        atomic_write_corpus_file(corpus, v1, prune=False)
        v2 = _make_jsonl([{"foo": i + 1} for i in range(10)])
        result = atomic_write_corpus_file(corpus, v2, prune=False)
        self.assertIsNone(result["unique_record_id_count_before"])
        self.assertIsNone(result["unique_record_id_count_after"])
        self.assertIsNone(result["record_id_field"])


class TestVerifierUniqueIdVerdicts(unittest.TestCase):
    """Integration tests: verifier emits correct verdict for dedup vs real loss."""

    def setUp(self):
        self._tmpdir = tempfile.TemporaryDirectory()
        self.tmp = Path(self._tmpdir.name)

    def tearDown(self):
        self._tmpdir.cleanup()

    def _write_log_entry(self, corpus: Path, entry: dict):
        """Directly append a rotation_log entry (for testing verifier logic)."""
        log = corpus.parent / (corpus.name + ".rotation_log.jsonl")
        with open(log, "a") as fh:
            fh.write(json.dumps(entry) + "\n")

    def test_pure_line_shrinkage_uid_stable_emits_warn(self):
        """Line count drops > 50% but unique IDs stable -> warn-line-shrinkage-but-uid-stable."""
        corpus = self.tmp / "corpus_dedup.jsonl"
        # Write 100-line/50-uid content
        corpus.write_bytes(_make_jsonl([{"invariant_id": f"INV-{i % 50}"} for i in range(100)]))
        # Fake rotation_log with byte_count=2000 (simulating prev larger file)
        # but uid_before=50 and uid_after=50 (stable)
        # The actual file is ~2680 bytes; use 6000 to trigger >50% shrinkage threshold
        self._write_log_entry(corpus, {
            "schema": "auditooor.r67_atomic_corpus_writer.v1",
            "ts": "20260526T000000Z",
            "byte_count": 6000,  # much larger than actual file to trigger line-shrink
            "prior_byte_count": 0,
            "backup_path": None,
            "sha256": "abc",
            "unique_record_id_count_before": 50,
            "unique_record_id_count_after": 50,
            "record_id_field": "invariant_id",
            "dedup_dropped_count": 50,
        })
        result = verify_file(corpus, freshness_hours=8760, shrinkage_ratio=0.5)
        self.assertEqual(result["verdict"], "warn-line-shrinkage-but-uid-stable")

    def test_real_uid_shrinkage_emits_fail(self):
        """Unique IDs drop > 5% -> fail-unique-id-shrinkage-over-5pct."""
        corpus = self.tmp / "corpus_loss.jsonl"
        corpus.write_bytes(_make_jsonl([{"invariant_id": f"INV-{i}"} for i in range(50)]))
        self._write_log_entry(corpus, {
            "schema": "auditooor.r67_atomic_corpus_writer.v1",
            "ts": "20260526T000000Z",
            "byte_count": 5000,  # larger to trigger shrinkage_pct check
            "prior_byte_count": 0,
            "backup_path": None,
            "sha256": "abc",
            "unique_record_id_count_before": 100,  # was 100
            "unique_record_id_count_after": 50,    # now 50 -> 50% loss > 5%
            "record_id_field": "invariant_id",
            "dedup_dropped_count": 0,
        })
        result = verify_file(corpus, freshness_hours=8760, shrinkage_ratio=0.5)
        self.assertEqual(result["verdict"], "fail-unique-id-shrinkage-over-5pct")

    def test_line_shrinkage_no_uid_data_emits_fail(self):
        """Line shrinkage > 50% with no UID data -> fail-shrinkage-over-50pct-no-log-entry."""
        corpus = self.tmp / "corpus_nouid.jsonl"
        corpus.write_bytes(_make_jsonl([{"foo": i} for i in range(10)]))
        self._write_log_entry(corpus, {
            "schema": "auditooor.r67_atomic_corpus_writer.v1",
            "ts": "20260526T000000Z",
            "byte_count": 5000,
            "prior_byte_count": 0,
            "backup_path": None,
            "sha256": "abc",
            # No uid fields present (old-format rotation_log entry)
        })
        result = verify_file(corpus, freshness_hours=8760, shrinkage_ratio=0.5)
        self.assertEqual(result["verdict"], "fail-shrinkage-over-50pct-no-log-entry")

    def test_stable_file_pass(self):
        """No shrinkage, fresh log -> pass-fresh-rotation-and-stable."""
        corpus = self.tmp / "corpus_stable.jsonl"
        records = [{"invariant_id": f"INV-{i}"} for i in range(20)]
        v1 = _make_jsonl(records)
        corpus.write_bytes(v1)
        self._write_log_entry(corpus, {
            "schema": "auditooor.r67_atomic_corpus_writer.v1",
            "ts": "20260526T120000Z",
            "byte_count": len(v1),
            "prior_byte_count": 0,
            "backup_path": None,
            "sha256": "abc",
            "unique_record_id_count_before": None,
            "unique_record_id_count_after": 20,
            "record_id_field": "invariant_id",
            "dedup_dropped_count": None,
        })
        result = verify_file(corpus, freshness_hours=8760, shrinkage_ratio=0.5)
        self.assertEqual(result["verdict"], "pass-fresh-rotation-and-stable")


if __name__ == "__main__":
    unittest.main()
