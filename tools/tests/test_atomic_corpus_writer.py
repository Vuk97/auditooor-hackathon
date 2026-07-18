# r36-rebuttal: LIFT-26 lane registered in .auditooor/agent_pathspec.json (lane-LIFT-26-R67); see tools/agent-pathspec-register.py list
"""Tests for tools/lib/atomic_corpus_writer.py (LIFT-26 / R67).

Coverage:
 1. atomic write happy path - file created with correct content + sha
 2. backup created on overwrite with timestamp + sha8 in name
 3. backup NOT created on first write (no prior file)
 4. sha256 verification fails -> AtomicWriteError, original untouched, no commit
 5. rotation_log.jsonl appended once per successful write with correct shape
 6. concurrent writes (2 threads) -> final state coherent, no partial files
 7. rotation prune: 12 auto backups + keep_last=10 + far-future TTL -> 10 kept
 8. TTL prune removes backups older than ttl_days
 9. .bak.pre-* backups always preserved by prune
10. list_backups returns both auto and pre- backups
11. find_corpus_writer_candidates returns tools touching derived/ stems
12. atomic_write does NOT leave .tmp.<uuid> files behind on success path
13. atomic_write content type validation (bytes/str/TypeError on int)
"""

from __future__ import annotations

import json
import os
import shutil
import tempfile
import threading
import time
import unittest
from datetime import datetime, timedelta, timezone
from pathlib import Path

# Path-fix: imports through tools.lib.<name> namespace.
import sys

_REPO = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(_REPO))

from tools.lib.atomic_corpus_writer import (  # noqa: E402
    AtomicWriteError,
    SCHEMA,
    atomic_write_corpus_file,
    find_corpus_writer_candidates,
    list_backups,
    prune_backups,
    read_rotation_log,
    rotation_log_path,
)


class AtomicWriteHappyPathTest(unittest.TestCase):
    def setUp(self):
        self.tmpdir = Path(tempfile.mkdtemp(prefix="r67-test-"))

    def tearDown(self):
        shutil.rmtree(self.tmpdir, ignore_errors=True)

    def test_first_write_creates_file(self):
        p = self.tmpdir / "corpus.jsonl"
        result = atomic_write_corpus_file(p, '{"x":1}\n')
        self.assertTrue(result["success"])
        self.assertEqual(result["schema"], SCHEMA)
        self.assertEqual(p.read_text(), '{"x":1}\n')
        # No backup on first write (no prior file).
        self.assertIsNone(result["backup_path"])
        self.assertEqual(result["prior_byte_count"], 0)
        # Rotation log was created.
        self.assertEqual(rotation_log_path(p), Path(str(p) + ".rotation_log.jsonl"))
        self.assertTrue(rotation_log_path(p).exists())

    def test_overwrite_creates_backup_with_sha8(self):
        p = self.tmpdir / "corpus.jsonl"
        atomic_write_corpus_file(p, "first\n")
        result = atomic_write_corpus_file(p, "second\n")
        self.assertEqual(p.read_text(), "second\n")
        self.assertIsNotNone(result["backup_path"])
        backup = Path(result["backup_path"])
        # Backup name: corpus.jsonl.bak.<utc>.<sha8>
        self.assertTrue(backup.name.startswith("corpus.jsonl.bak."))
        # Format: name.bak.YYYYMMDDTHHMMSSZ.SHA8
        parts = backup.name.split(".bak.")[-1].split(".")
        self.assertEqual(len(parts[0]), 16)  # 20260526T193000Z = 16 chars
        self.assertEqual(len(parts[1]), 8)  # sha8
        # Backup contains FIRST content.
        self.assertEqual(backup.read_text(), "first\n")

    def test_no_backup_first_explicit_disable(self):
        p = self.tmpdir / "corpus.jsonl"
        atomic_write_corpus_file(p, "first\n")
        result = atomic_write_corpus_file(p, "second\n", backup_first=False)
        self.assertIsNone(result["backup_path"])
        self.assertEqual(p.read_text(), "second\n")

    def test_sha_mismatch_raises_and_preserves_original(self):
        p = self.tmpdir / "corpus.jsonl"
        atomic_write_corpus_file(p, "first\n")
        bogus_sha = "0" * 64
        with self.assertRaises(AtomicWriteError):
            atomic_write_corpus_file(p, "second\n", expected_sha256=bogus_sha)
        # Original is preserved.
        self.assertEqual(p.read_text(), "first\n")
        # No partial .tmp files left.
        tmps = list(self.tmpdir.glob("corpus.jsonl.tmp.*"))
        self.assertEqual(tmps, [])

    def test_rotation_log_record_shape(self):
        p = self.tmpdir / "corpus.jsonl"
        atomic_write_corpus_file(p, "v1\n")
        atomic_write_corpus_file(p, "v2 longer\n")
        log = read_rotation_log(p)
        self.assertEqual(len(log), 2)
        # First entry: prior_byte_count = 0, byte_count = 3.
        self.assertEqual(log[0]["prior_byte_count"], 0)
        self.assertEqual(log[0]["byte_count"], 3)
        # Second entry: prior_byte_count = 3, byte_count = 10.
        self.assertEqual(log[1]["prior_byte_count"], 3)
        self.assertEqual(log[1]["byte_count"], 10)
        # All entries have schema/ts/path/sha256.
        for entry in log:
            self.assertEqual(entry["schema"], SCHEMA)
            self.assertIn("ts", entry)
            self.assertIn("sha256", entry)
            self.assertEqual(entry["path"], str(p))

    def test_no_tmp_file_left_behind_on_success(self):
        p = self.tmpdir / "corpus.jsonl"
        atomic_write_corpus_file(p, "first\n")
        tmps = list(self.tmpdir.glob("corpus.jsonl.tmp.*"))
        self.assertEqual(tmps, [])

    def test_content_type_validation(self):
        p = self.tmpdir / "corpus.jsonl"
        # str OK.
        atomic_write_corpus_file(p, "ok\n")
        # bytes OK.
        atomic_write_corpus_file(p, b"bytes-ok\n")
        # int should raise.
        with self.assertRaises(TypeError):
            atomic_write_corpus_file(p, 42)


class ConcurrentWriteTest(unittest.TestCase):
    def setUp(self):
        self.tmpdir = Path(tempfile.mkdtemp(prefix="r67-conc-"))

    def tearDown(self):
        shutil.rmtree(self.tmpdir, ignore_errors=True)

    def test_two_concurrent_writes_no_corruption(self):
        """Two simultaneous writes: final state must equal one of the inputs."""
        p = self.tmpdir / "corpus.jsonl"
        atomic_write_corpus_file(p, "seed\n")
        errors: list[Exception] = []

        def write_a():
            try:
                atomic_write_corpus_file(p, "A" * 100 + "\n")
            except Exception as e:
                errors.append(e)

        def write_b():
            try:
                atomic_write_corpus_file(p, "B" * 100 + "\n")
            except Exception as e:
                errors.append(e)

        t1 = threading.Thread(target=write_a)
        t2 = threading.Thread(target=write_b)
        t1.start()
        t2.start()
        t1.join()
        t2.join()
        self.assertEqual(errors, [])
        # Final content is one of the two complete writes (not a mix).
        final = p.read_text()
        self.assertIn(final, ("A" * 100 + "\n", "B" * 100 + "\n"))
        # No .tmp.<uuid> files left.
        tmps = list(self.tmpdir.glob("corpus.jsonl.tmp.*"))
        self.assertEqual(tmps, [])


class PrunePolicyTest(unittest.TestCase):
    def setUp(self):
        self.tmpdir = Path(tempfile.mkdtemp(prefix="r67-prune-"))
        self.target = self.tmpdir / "corpus.jsonl"
        self.target.write_text("seed\n")

    def tearDown(self):
        shutil.rmtree(self.tmpdir, ignore_errors=True)

    def _make_auto_backup(self, ts: datetime, sha8: str = "abcdef01") -> Path:
        """Create a faux auto-rotated backup with embedded timestamp."""
        utc = ts.strftime("%Y%m%dT%H%M%SZ")
        name = f"{self.target.name}.bak.{utc}.{sha8}"
        backup = self.tmpdir / name
        backup.write_text("auto-backup\n")
        # Set mtime to match the embedded timestamp.
        os.utime(backup, (ts.timestamp(), ts.timestamp()))
        return backup

    def _make_pre_backup(self, tag: str) -> Path:
        name = f"{self.target.name}.bak.pre-{tag}"
        backup = self.tmpdir / name
        backup.write_text("manual-pre-backup\n")
        return backup

    def test_keep_last_10_with_12_backups(self):
        """12 auto backups + far-future TTL -> 10 kept, 2 pruned."""
        base = datetime(2026, 5, 26, tzinfo=timezone.utc)
        # Create 12 auto backups, each 1 minute apart.
        for i in range(12):
            self._make_auto_backup(base - timedelta(minutes=i), sha8=f"{i:08x}")
        result = prune_backups(self.target, keep_last=10, ttl_days=365)
        # 10 kept, 2 pruned (the oldest two).
        self.assertEqual(len(result["kept"]), 10)
        self.assertEqual(len(result["pruned"]), 2)

    def test_ttl_prunes_old_backups(self):
        """Backups older than ttl_days are pruned, fresh ones kept."""
        # Create 3 backups: 30d old, 5d old, today.
        old = self._make_auto_backup(
            datetime.now(timezone.utc) - timedelta(days=30), sha8="00000001"
        )
        mid = self._make_auto_backup(
            datetime.now(timezone.utc) - timedelta(days=5), sha8="00000002"
        )
        new = self._make_auto_backup(
            datetime.now(timezone.utc) - timedelta(minutes=1), sha8="00000003"
        )
        result = prune_backups(self.target, keep_last=2, ttl_days=14)
        kept_paths = {b.name for b in result["kept"]}
        pruned_paths = {b.name for b in result["pruned"]}
        # Newest 2 kept (mid + new) by keep_last floor; the 30d one is pruned.
        self.assertIn(new.name, kept_paths)
        self.assertIn(mid.name, kept_paths)
        self.assertIn(old.name, pruned_paths)
        self.assertFalse(old.exists())

    def test_pre_backups_preserved(self):
        """`.bak.pre-*` backups are never pruned."""
        pre = self._make_pre_backup("quarantine-2026-05-26")
        # Create many old auto backups to trigger pruning aggressively.
        for i in range(15):
            self._make_auto_backup(
                datetime.now(timezone.utc) - timedelta(days=30 + i),
                sha8=f"{i:08x}",
            )
        result = prune_backups(self.target, keep_last=2, ttl_days=14)
        manual_names = {p.name for p in result["manual_preserved"]}
        self.assertIn(pre.name, manual_names)
        self.assertTrue(pre.exists())

    def test_list_backups_returns_both_kinds(self):
        self._make_pre_backup("safety")
        self._make_auto_backup(datetime.now(timezone.utc), sha8="abcdef01")
        backups = list_backups(self.target)
        self.assertEqual(len(backups), 2)
        names = {b.name for b in backups}
        self.assertTrue(any("pre-safety" in n for n in names))
        self.assertTrue(any(".bak.2" in n for n in names))


class WriterCandidateScanTest(unittest.TestCase):
    def setUp(self):
        self.tmpdir = Path(tempfile.mkdtemp(prefix="r67-scan-"))
        (self.tmpdir / "tools").mkdir()

    def tearDown(self):
        shutil.rmtree(self.tmpdir, ignore_errors=True)

    def test_find_writer_candidates(self):
        # Tool 1: writes to invariants_pilot_audited with open(..., 'w').
        (self.tmpdir / "tools" / "miner.py").write_text(
            "import json\n"
            "path = 'audit/corpus_tags/derived/invariants_pilot_audited.jsonl'\n"
            "with open(path, 'w') as fh:\n"
            "    fh.write('row\\n')\n"
        )
        # Tool 2: only reads, no writes.
        (self.tmpdir / "tools" / "reader.py").write_text(
            "import json\n"
            "path = 'audit/corpus_tags/derived/invariants_pilot_audited.jsonl'\n"
            "with open(path, 'r') as fh:\n"
            "    data = fh.read()\n"
        )
        # Tool 3: writes to something else.
        (self.tmpdir / "tools" / "unrelated.py").write_text(
            "open('foo.txt', 'w').write('x')\n"
        )
        candidates = find_corpus_writer_candidates(self.tmpdir)
        names = {p.name for p in candidates}
        self.assertIn("miner.py", names)
        # reader.py has the corpus stem reference but also has `open(` which is
        # a write idiom (used here for read). The classifier accepts that as a
        # candidate because callers should review. Not strict.
        # unrelated.py has no corpus stem -> excluded.
        self.assertNotIn("unrelated.py", names)


if __name__ == "__main__":
    unittest.main()
