"""backfill-tier-registry.py — `--dry-run` + snapshot guard tests.

Background — quoted from auto-improvement queue iter 4
(2026-04-25_23:17:56), Minimax idea 2:

    File: tools/backfill-tier-registry.py
    What: The backfill script iterates all detectors and overwrites
    _tier_registry.yaml tier labels in-place. If it crashes mid-run ...
    no transaction log, no rollback.
    Fix: Add `--dry-run` flag that prints what WOULD change. Before
    writing, snapshot the registry to ~/.cache/audit-tiers/backup-<ts>.yaml.
    Success criterion: `backfill-tier-registry.py --dry-run` on a clean
    repo produces a diff without modifying any file.

Kimi precheck (GAP-CONFIRMED):
    `tools/backfill-tier-registry.py` writes `detectors/_tier_registry.yaml`
    in-place at line 217 (`REGISTRY.write_text(...)`). Searched for
    `--dry-run`, `backup`, `rollback`, `snapshot`, `argparse`: none
    present. The script has no CLI flags and no transaction guard.

Calibration: Kimi-grep-prechecked. Kimi has 0/3 audit-style FP rate but
a higher rate on idea-prechecks. Supervisor verified by reading the
file (no `argparse`, single in-place `write_text`) before shipping.

These tests cover:
  1. Argparse plumbing: `--dry-run` + `--backup-dir` parse without error.
  2. `_snapshot_registry`: copies the live registry into a timestamped
     file under the backup dir, returns None on a missing source.
"""
from __future__ import annotations

import importlib.util
import sys
import tempfile
import types
import unittest
from pathlib import Path


REPO = Path(__file__).resolve().parents[2]
TOOL = REPO / "tools" / "backfill-tier-registry.py"


def _load_module() -> types.ModuleType:
    tools_dir = str(REPO / "tools")
    if tools_dir not in sys.path:
        sys.path.insert(0, tools_dir)
    spec = importlib.util.spec_from_file_location("backfill_tier_registry", TOOL)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


class ArgparseTest(unittest.TestCase):

    @classmethod
    def setUpClass(cls) -> None:
        cls.t = _load_module()

    def test_default_args(self) -> None:
        ns = self.t._parse_args([])
        self.assertFalse(ns.dry_run)
        self.assertEqual(ns.backup_dir, Path("~/.cache/audit-tiers"))

    def test_dry_run_flag(self) -> None:
        ns = self.t._parse_args(["--dry-run"])
        self.assertTrue(ns.dry_run)

    def test_custom_backup_dir(self) -> None:
        ns = self.t._parse_args(["--backup-dir", "/tmp/my-cache"])
        self.assertEqual(ns.backup_dir, Path("/tmp/my-cache"))


class SnapshotTest(unittest.TestCase):

    @classmethod
    def setUpClass(cls) -> None:
        cls.t = _load_module()

    def test_snapshot_copies_existing_registry(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            tmp = Path(tmp)
            # Synthesize a fake registry file with non-trivial bytes.
            registry = tmp / "registry.yaml"
            payload = b"version: 1\ntiers:\n  alpha: {tier: S}\n"
            registry.write_bytes(payload)

            backup_dir = tmp / "cache"
            dest = self.t._snapshot_registry(backup_dir, registry)

            self.assertIsNotNone(dest, "snapshot must succeed when source exists")
            self.assertTrue(dest.exists())
            self.assertEqual(dest.read_bytes(), payload)
            # Filename format: backup-YYYYMMDDTHHMMSS.yaml
            self.assertTrue(dest.name.startswith("backup-"))
            self.assertTrue(dest.name.endswith(".yaml"))

    def test_snapshot_skips_when_source_missing(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            tmp = Path(tmp)
            missing = tmp / "no-registry.yaml"
            backup_dir = tmp / "cache"
            dest = self.t._snapshot_registry(backup_dir, missing)
            self.assertIsNone(dest)
            # Should NOT have created the backup directory either.
            self.assertFalse(backup_dir.exists())


if __name__ == "__main__":
    unittest.main()
