"""Tests for tools/derived-artifact-size-budget.py (J3e).

Covers:
  1. Empty derived root - no crash, empty summary
  2. Artifact within budget - verdict within_budget
  3. Artifact over soft budget - verdict over_soft_budget + remediation present
  4. Artifact over hard budget - verdict over_hard_budget + closeout_blockers
  5. Total-budget breach - total_verdict over_hard_budget
  6. Strict mode - exit code non-zero on hard breach
  7. Remediation recommendation present for over-budget artifact
  8. JSON schema fields present (schema, root, budgets, artifacts, summary, closeout_blockers)
  9. Missing root - graceful missing info (no crash)
 10. Sharded directory treated as single artifact unit
"""
from __future__ import annotations

import json
import os
import sys
import tempfile
import unittest
from pathlib import Path

# Ensure tools/ is importable
_TOOLS_DIR = Path(__file__).resolve().parent.parent
if str(_TOOLS_DIR) not in sys.path:
    sys.path.insert(0, str(_TOOLS_DIR))

# Import the module under test by its hyphenated filename
import importlib.util

_MOD_PATH = _TOOLS_DIR / "derived-artifact-size-budget.py"
_spec = importlib.util.spec_from_file_location("derived_artifact_size_budget", _MOD_PATH)
_mod = importlib.util.module_from_spec(_spec)  # type: ignore[arg-type]
_spec.loader.exec_module(_mod)  # type: ignore[union-attr]

check_artifacts = _mod.check_artifacts
main = _mod.main
SCHEMA_VERSION = _mod.SCHEMA_VERSION

# Convenient budget constants for tests
SOFT = 10 * 1024  # 10 KB soft budget
HARD = 50 * 1024  # 50 KB hard budget
TOTAL = 200 * 1024  # 200 KB total


def _write_file(path: Path, size_bytes: int) -> None:
    """Write a synthetic file of the given size."""
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("wb") as fh:
        fh.write(b"x" * size_bytes)


class TestEmptyRoot(unittest.TestCase):
    """Case 1: Empty derived root directory."""

    def test_empty_dir_no_crash(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp) / "derived"
            root.mkdir()
            report = check_artifacts(root, soft_bytes=SOFT, hard_bytes=HARD, total_bytes=TOTAL)
            self.assertEqual(report["schema"], SCHEMA_VERSION)
            self.assertEqual(report["artifacts"], [])
            self.assertIsNone(report["error"])
            self.assertEqual(report["summary"]["total_artifacts"], 0)
            self.assertEqual(report["summary"]["total_verdict"], "within_budget")


class TestWithinBudget(unittest.TestCase):
    """Case 2: Single artifact under soft budget."""

    def test_small_artifact_within_budget(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp) / "derived"
            root.mkdir()
            _write_file(root / "small.jsonl", 1024)  # 1 KB - under SOFT=10 KB
            report = check_artifacts(root, soft_bytes=SOFT, hard_bytes=HARD, total_bytes=TOTAL)
            self.assertEqual(len(report["artifacts"]), 1)
            self.assertEqual(report["artifacts"][0]["verdict"], "within_budget")
            self.assertEqual(report["summary"]["within_budget"], 1)
            self.assertEqual(report["summary"]["over_soft_budget"], 0)
            self.assertEqual(report["summary"]["over_hard_budget"], 0)


class TestOverSoftBudget(unittest.TestCase):
    """Case 3: Artifact over soft but under hard budget."""

    def test_over_soft_verdict_and_remediation(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp) / "derived"
            root.mkdir()
            # 20 KB: above SOFT(10 KB) but below HARD(50 KB)
            _write_file(root / "medium.jsonl", 20 * 1024)
            report = check_artifacts(root, soft_bytes=SOFT, hard_bytes=HARD, total_bytes=TOTAL)
            self.assertEqual(len(report["artifacts"]), 1)
            a = report["artifacts"][0]
            self.assertEqual(a["verdict"], "over_soft_budget")
            # Case 7: remediation must be a non-empty string
            self.assertIn("remediation", a)
            self.assertTrue(a["remediation"])


class TestOverHardBudget(unittest.TestCase):
    """Case 4: Artifact over hard budget -> closeout_blockers populated."""

    def test_over_hard_closeout_blocker(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp) / "derived"
            root.mkdir()
            # 80 KB: above HARD=50 KB
            _write_file(root / "big.jsonl", 80 * 1024)
            report = check_artifacts(root, soft_bytes=SOFT, hard_bytes=HARD, total_bytes=TOTAL)
            self.assertEqual(len(report["artifacts"]), 1)
            a = report["artifacts"][0]
            self.assertEqual(a["verdict"], "over_hard_budget")
            self.assertIn("big.jsonl", report["closeout_blockers"])
            self.assertEqual(report["summary"]["over_hard_budget"], 1)


class TestShardedDirPerShardBudget(unittest.TestCase):
    """Sharded .d/ directories are judged on the largest SHARD, not the
    directory total - bounded per-file load is the point of sharding."""

    def test_sharded_dir_within_budget_when_each_shard_under_hard(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp) / "derived"
            root.mkdir()
            # A sharded unit: 20 shards x 8 KB = 160 KB total (over HARD=50 KB
            # in aggregate) but every shard is under the soft + hard budget.
            shard_dir = root / "big_sidecar.d"
            shard_dir.mkdir()
            for i in range(20):
                _write_file(shard_dir / f"shard-{i:05d}.jsonl", 8 * 1024)
            (root / "big_sidecar.manifest.json").write_text("{}", encoding="utf-8")
            report = check_artifacts(root, soft_bytes=SOFT, hard_bytes=HARD, total_bytes=10 * 1024 * 1024)
            rows = [a for a in report["artifacts"] if a["name"] == "big_sidecar.d"]
            self.assertEqual(len(rows), 1)
            a = rows[0]
            self.assertEqual(a["verdict"], "within_budget")
            self.assertEqual(a["remediation"], "already_sharded")
            self.assertEqual(a["shard_count"], 20)
            self.assertNotIn("big_sidecar.d", report["closeout_blockers"])

    def test_sharded_dir_over_hard_when_a_shard_exceeds_budget(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp) / "derived"
            root.mkdir()
            shard_dir = root / "bad_sidecar.d"
            shard_dir.mkdir()
            _write_file(shard_dir / "shard-00000.jsonl", 10 * 1024)
            _write_file(shard_dir / "shard-00001.jsonl", 80 * 1024)  # over HARD
            (root / "bad_sidecar.manifest.json").write_text("{}", encoding="utf-8")
            report = check_artifacts(root, soft_bytes=SOFT, hard_bytes=HARD, total_bytes=10 * 1024 * 1024)
            rows = [a for a in report["artifacts"] if a["name"] == "bad_sidecar.d"]
            self.assertEqual(len(rows), 1)
            self.assertEqual(rows[0]["verdict"], "over_hard_budget")
            self.assertIn("bad_sidecar.d", report["closeout_blockers"])


class TestTotalBudgetBreach(unittest.TestCase):
    """Case 5: Multiple small files whose combined size exceeds total budget."""

    def test_total_budget_breach(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp) / "derived"
            root.mkdir()
            # 3 files x 40 KB each = 120 KB, each under HARD(50 KB), total over TOTAL(200 KB)...
            # Actually 120 KB < 200 KB, so use 5 x 40 KB = 200 KB (boundary) or push to 250 KB
            for i in range(5):
                _write_file(root / f"chunk_{i}.jsonl", 45 * 1024)  # 5 x 45 KB = 225 KB > 200 KB
            report = check_artifacts(root, soft_bytes=SOFT, hard_bytes=HARD, total_bytes=TOTAL)
            self.assertEqual(report["summary"]["total_verdict"], "over_hard_budget")
            self.assertIn("__total__", report["closeout_blockers"])


class TestStrictModeExit(unittest.TestCase):
    """Case 6: --strict flag causes non-zero exit when a hard-budget blocker exists."""

    def test_strict_nonzero_on_hard_breach(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp) / "derived"
            root.mkdir()
            _write_file(root / "giant.jsonl", 80 * 1024)  # over HARD
            argv = [
                "--root", str(root),
                "--per-artifact-budget-mb", str(SOFT / (1024 * 1024)),
                "--hard-artifact-budget-mb", str(HARD / (1024 * 1024)),
                "--total-budget-mb", str(TOTAL / (1024 * 1024)),
                "--strict",
            ]
            rc = main(argv)
            self.assertEqual(rc, 1)

    def test_strict_zero_when_all_within_budget(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp) / "derived"
            root.mkdir()
            _write_file(root / "tiny.jsonl", 512)  # well under SOFT
            argv = [
                "--root", str(root),
                "--per-artifact-budget-mb", str(SOFT / (1024 * 1024)),
                "--hard-artifact-budget-mb", str(HARD / (1024 * 1024)),
                "--total-budget-mb", str(TOTAL / (1024 * 1024)),
                "--strict",
            ]
            rc = main(argv)
            self.assertEqual(rc, 0)


class TestRemediationPresence(unittest.TestCase):
    """Case 7: Over-budget artifacts always have a remediation recommendation."""

    def test_remediation_always_present(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp) / "derived"
            root.mkdir()
            # One over-soft, one over-hard
            _write_file(root / "over_soft.jsonl", 20 * 1024)
            _write_file(root / "over_hard.jsonl", 80 * 1024)
            report = check_artifacts(root, soft_bytes=SOFT, hard_bytes=HARD, total_bytes=TOTAL)
            for a in report["artifacts"]:
                self.assertIn("remediation", a, f"Missing remediation on {a['name']}")
                self.assertIsInstance(a["remediation"], str)
                self.assertTrue(a["remediation"], f"Empty remediation on {a['name']}")


class TestJsonSchemaFields(unittest.TestCase):
    """Case 8: JSON output contains all required schema fields."""

    def test_required_schema_fields_present(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp) / "derived"
            root.mkdir()
            _write_file(root / "sample.jsonl", 5 * 1024)
            report = check_artifacts(root, soft_bytes=SOFT, hard_bytes=HARD, total_bytes=TOTAL)

            # Top-level required fields
            for field in ("schema", "root", "budgets", "artifacts", "summary", "closeout_blockers", "error"):
                self.assertIn(field, report, f"Missing top-level field: {field}")

            self.assertEqual(report["schema"], SCHEMA_VERSION)

            # Budget sub-fields
            for key in ("per_artifact_soft_bytes", "per_artifact_hard_bytes", "total_bytes"):
                self.assertIn(key, report["budgets"], f"Missing budget field: {key}")

            # Summary sub-fields
            for key in ("total_artifacts", "within_budget", "over_soft_budget",
                        "over_hard_budget", "total_size_bytes", "total_verdict"):
                self.assertIn(key, report["summary"], f"Missing summary field: {key}")

            # Artifact row fields
            for a in report["artifacts"]:
                for key in ("name", "path", "size_bytes", "size_mb",
                            "is_sharded_dir", "verdict", "remediation"):
                    self.assertIn(key, a, f"Missing artifact field: {key}")


class TestMissingRoot(unittest.TestCase):
    """Case 9: Non-existent root path - graceful missing info, no crash."""

    def test_missing_root_no_crash(self) -> None:
        root = Path("/tmp/__auditooor_nonexistent_derived_dir_xyz_12345__")
        report = check_artifacts(root, soft_bytes=SOFT, hard_bytes=HARD, total_bytes=TOTAL)
        self.assertIsNotNone(report["error"])
        self.assertIn("does not exist", report["error"])
        self.assertEqual(report["summary"]["total_verdict"], "missing")
        # Schema field must still be present
        self.assertEqual(report["schema"], SCHEMA_VERSION)

    def test_missing_root_json_mode_no_crash(self) -> None:
        """--json flag on missing root should still emit valid JSON."""
        root = Path("/tmp/__auditooor_nonexistent_derived_dir_xyz_99999__")
        # Redirect stdout to capture
        import io
        from contextlib import redirect_stdout
        buf = io.StringIO()
        argv = ["--root", str(root), "--json"]
        with redirect_stdout(buf):
            rc = main(argv)
        output = buf.getvalue()
        # Must be parseable JSON
        data = json.loads(output)
        self.assertIn("schema", data)
        self.assertEqual(rc, 0)  # non-strict: no error exit even on missing root


class TestShardedDirectoryUnit(unittest.TestCase):
    """Case 10: Sharded directory (.d/) with manifest treated as single unit."""

    def test_sharded_dir_measured_as_unit(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp) / "derived"
            root.mkdir()
            # Simulate sharded layout: exploit_predicates.d/ + manifest + stub .jsonl
            shard_dir = root / "exploit_predicates.d"
            shard_dir.mkdir()
            # Write two 5 KB shards = 10 KB total for the dir (within HARD=50 KB)
            _write_file(shard_dir / "shard-00000.jsonl", 5 * 1024)
            _write_file(shard_dir / "shard-00001.jsonl", 5 * 1024)
            # Manifest file (belongs to sharded unit, should NOT be a separate artifact)
            _write_file(root / "exploit_predicates.manifest.json", 512)
            # Monolith stub (should NOT be a separate artifact when shard dir exists)
            _write_file(root / "exploit_predicates.jsonl", 1024)

            report = check_artifacts(root, soft_bytes=SOFT, hard_bytes=HARD, total_bytes=TOTAL)

            names = [a["name"] for a in report["artifacts"]]
            # The shard dir should appear
            self.assertIn("exploit_predicates.d", names)
            # The manifest and monolith stub should NOT appear as separate artifacts
            self.assertNotIn("exploit_predicates.manifest.json", names)
            self.assertNotIn("exploit_predicates.jsonl", names)

            # The shard dir artifact should be flagged as is_sharded_dir=True
            shard_artifact = next(a for a in report["artifacts"] if a["name"] == "exploit_predicates.d")
            self.assertTrue(shard_artifact["is_sharded_dir"])

    def test_sharded_dir_within_budget_remediation(self) -> None:
        """A sharded dir within budget has remediation = already_sharded."""
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp) / "derived"
            root.mkdir()
            shard_dir = root / "predicates.d"
            shard_dir.mkdir()
            _write_file(shard_dir / "shard-00000.jsonl", 1024)  # tiny, within budget
            report = check_artifacts(root, soft_bytes=SOFT, hard_bytes=HARD, total_bytes=TOTAL)
            a = next(a for a in report["artifacts"] if a["name"] == "predicates.d")
            self.assertEqual(a["remediation"], "already_sharded")


if __name__ == "__main__":
    unittest.main()
