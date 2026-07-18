"""Tests for tools/capv3-iter-ledger-emit.py (PR #658 Tier-B #4).

Covers:
- Parsing CAPV3_ITER*.md fixtures to build ledger rows
- Schema validation of emitted rows via universal-task-ledger-validate.py
- --filter-priority returns highest-numbered open ITER
- --json emits valid JSONL to stdout
- --apply writes/merges into a temp ledger file
- Done-marker detection (all-done vs partial-done ITER)
"""
from __future__ import annotations

import json
import os
import pathlib
import subprocess
import sys
import tempfile
import unittest

REPO = pathlib.Path(__file__).resolve().parents[2]
TOOL = REPO / "tools" / "capv3-iter-ledger-emit.py"
VALIDATOR = REPO / "tools" / "universal-task-ledger-validate.py"


def _run(*args, docs_dir: str | None = None) -> tuple[int, str, str]:
    """Run capv3-iter-ledger-emit.py with given args; return (rc, stdout, stderr)."""
    cmd = [sys.executable, str(TOOL)] + list(args)
    if docs_dir is not None:
        cmd += ["--workspace", docs_dir]
    proc = subprocess.run(cmd, capture_output=True, text=True)
    return proc.returncode, proc.stdout, proc.stderr


def _make_fixture_dir(tmp: pathlib.Path, iters: dict) -> pathlib.Path:
    """Build a synthetic docs/ directory with CAPV3 ITER fixtures.

    iters: {iter_num: [(task_num, slug, content), ...]}
    """
    docs = tmp / "docs"
    docs.mkdir()
    for iter_num, tasks in iters.items():
        for task_num, slug, content in tasks:
            fname = f"CAPV3_ITER{iter_num}_T{task_num}_{slug}.md"
            (docs / fname).write_text(content, encoding="utf-8")
    return tmp


class TestCapV3IterLedgerEmitParsing(unittest.TestCase):
    """Tests that cover ITER parsing and row construction."""

    def _make_ws(self, iters: dict) -> pathlib.Path:
        """Create a minimal fake workspace with docs/ + tools/ symlinks."""
        tmp = pathlib.Path(tempfile.mkdtemp())
        self._tmpdirs = getattr(self, "_tmpdirs", [])
        self._tmpdirs.append(tmp)
        _make_fixture_dir(tmp, iters)
        # symlink tools/ so validator is reachable from fake workspace
        (tmp / "tools").symlink_to(REPO / "tools")
        (tmp / "schemas").symlink_to(REPO / "schemas")
        (tmp / ".auditooor").mkdir()
        return tmp

    def tearDown(self):
        import shutil
        for d in getattr(self, "_tmpdirs", []):
            shutil.rmtree(d, ignore_errors=True)

    def test_parses_single_iter_emits_valid_row(self):
        """A single ITER with 2 tasks should emit exactly 1 valid ledger row."""
        ws = self._make_ws({
            4: [
                (1, "fuzz_run", "# CAPV3 iter-4 T1\n\nSome content here.\n"),
                (2, "adversarial_rerun", "# CAPV3 iter-4 T2\n\nSome content.\n"),
            ]
        })
        rc, stdout, stderr = _run("--json", "--workspace", str(ws))
        self.assertEqual(rc, 0, f"expected 0, got {rc}; stderr:\n{stderr}")
        rows = [json.loads(line) for line in stdout.splitlines() if line.strip()]
        self.assertEqual(len(rows), 1)
        row = rows[0]
        self.assertEqual(row["schema"], "auditooor.universal_task_ledger.v1")
        self.assertEqual(row["type"], "next_loop_priority")
        self.assertIn("capv3-iter04", row["id"])

    def test_schema_validates_against_validator(self):
        """Emitted rows must pass universal-task-ledger-validate.py."""
        ws = self._make_ws({
            4: [(1, "some_task", "# T1\n\nContent.\n")]
        })
        rc, stdout, stderr = _run("--json", "--workspace", str(ws))
        self.assertEqual(rc, 0, f"json emit failed; stderr:\n{stderr}")
        rows = [json.loads(line) for line in stdout.splitlines() if line.strip()]
        self.assertGreater(len(rows), 0)

        # Validate each row independently via the validator
        with tempfile.NamedTemporaryFile(
            mode="w", suffix=".jsonl", delete=False
        ) as fh:
            for r in rows:
                fh.write(json.dumps(r) + "\n")
            tmppath = fh.name
        try:
            proc = subprocess.run(
                [sys.executable, str(VALIDATOR), tmppath],
                capture_output=True,
                text=True,
            )
            self.assertEqual(
                proc.returncode, 0,
                f"validator failed; stderr:\n{proc.stderr}",
            )
        finally:
            os.unlink(tmppath)

    def test_filter_priority_returns_highest_open(self):
        """--filter-priority should return the highest-numbered open ITER."""
        ws = self._make_ws({
            3: [(1, "task_a", "# open content\n")],
            7: [(1, "task_b", "# open content\n")],
            5: [(1, "task_c", "# open content\n")],
        })
        rc, stdout, stderr = _run("--filter-priority", "--workspace", str(ws))
        self.assertEqual(rc, 0, f"stderr:\n{stderr}")
        self.assertEqual(stdout.strip(), "7")

    def test_filter_priority_none_when_all_done(self):
        """--filter-priority should print 'none' when every ITER is shipped."""
        done_content = "# T1\n\n**Shipped**\n\nSome text.\n"
        ws = self._make_ws({
            2: [(1, "task_a", done_content)],
        })
        rc, stdout, stderr = _run("--filter-priority", "--workspace", str(ws))
        self.assertEqual(rc, 0, f"stderr:\n{stderr}")
        self.assertEqual(stdout.strip(), "none")

    def test_multiple_iters_emitted(self):
        """Multiple ITER groups should each produce exactly one row."""
        ws = self._make_ws({
            3: [(1, "t1", "# T1\n")],
            5: [(1, "t1", "# T1\n"), (2, "t2", "# T2\n")],
            9: [(1, "t1", "# T1\n")],
        })
        rc, stdout, stderr = _run("--json", "--workspace", str(ws))
        self.assertEqual(rc, 0, f"stderr:\n{stderr}")
        rows = [json.loads(line) for line in stdout.splitlines() if line.strip()]
        self.assertEqual(len(rows), 3)
        ids = {r["id"] for r in rows}
        self.assertTrue(any("capv3-iter03" in i for i in ids))
        self.assertTrue(any("capv3-iter05" in i for i in ids))
        self.assertTrue(any("capv3-iter09" in i for i in ids))

    def test_done_iter_has_shipped_status(self):
        """An ITER where all tasks show **Shipped** should have status=shipped."""
        done_content = "# T1\n\n**Shipped**\n"
        ws = self._make_ws({
            6: [(1, "done_task", done_content), (2, "also_done", done_content)],
        })
        rc, stdout, stderr = _run("--json", "--workspace", str(ws))
        self.assertEqual(rc, 0, f"stderr:\n{stderr}")
        rows = [json.loads(line) for line in stdout.splitlines() if line.strip()]
        self.assertEqual(len(rows), 1)
        self.assertEqual(rows[0]["status"], "shipped")
        self.assertEqual(rows[0]["status_substate"], "done")

    def test_partial_done_iter_is_in_progress(self):
        """An ITER where only some tasks are done should be in-progress."""
        done = "# T1\n\n**Shipped**\n"
        open_task = "# T2\n\nWork in progress.\n"
        ws = self._make_ws({
            8: [(1, "done", done), (2, "open", open_task)],
        })
        rc, stdout, stderr = _run("--json", "--workspace", str(ws))
        self.assertEqual(rc, 0, f"stderr:\n{stderr}")
        rows = [json.loads(line) for line in stdout.splitlines() if line.strip()]
        self.assertEqual(rows[0]["status"], "in-progress")

    def test_no_docs_dir_exits_2(self):
        """If docs/ has no CAPV3 files, tool should exit with code 2."""
        with tempfile.TemporaryDirectory() as tmpdir:
            ws = pathlib.Path(tmpdir)
            (ws / "docs").mkdir()
            (ws / "tools").symlink_to(REPO / "tools")
            (ws / "schemas").symlink_to(REPO / "schemas")
            (ws / ".auditooor").mkdir()
            rc, stdout, stderr = _run("--json", "--workspace", str(ws))
            self.assertEqual(rc, 2, f"expected exit 2 for empty docs/; stderr:\n{stderr}")

    def test_apply_writes_ledger_file(self):
        """--apply should create the ledger file and write rows into it."""
        ws = self._make_ws({
            4: [(1, "task_alpha", "# T1\n\nContent.\n")],
        })
        ledger = ws / ".auditooor" / "universal_task_ledger.jsonl"
        rc, stdout, stderr = _run(
            "--apply", "--ledger", str(ledger), "--workspace", str(ws)
        )
        self.assertEqual(rc, 0, f"stderr:\n{stderr}")
        self.assertTrue(ledger.is_file(), "ledger file was not created")
        rows = [json.loads(line) for line in ledger.read_text().splitlines() if line.strip()]
        self.assertEqual(len(rows), 1)
        self.assertIn("capv3-iter04", rows[0]["id"])

    def test_apply_merges_without_duplicates(self):
        """Running --apply twice should not duplicate rows in the ledger."""
        ws = self._make_ws({
            4: [(1, "task_alpha", "# T1\n")],
        })
        ledger = ws / ".auditooor" / "universal_task_ledger.jsonl"
        _run("--apply", "--ledger", str(ledger), "--workspace", str(ws))
        _run("--apply", "--ledger", str(ledger), "--workspace", str(ws))
        rows = [json.loads(line) for line in ledger.read_text().splitlines() if line.strip()]
        self.assertEqual(len(rows), 1, "duplicate rows after second --apply")

    def test_title_within_bounds(self):
        """Emitted title must be between 8 and 120 characters."""
        ws = self._make_ws({
            4: [(1, "x" * 60, "# T1\n")],
        })
        rc, stdout, stderr = _run("--json", "--workspace", str(ws))
        self.assertEqual(rc, 0, f"stderr:\n{stderr}")
        rows = [json.loads(line) for line in stdout.splitlines() if line.strip()]
        title = rows[0]["title"]
        self.assertGreaterEqual(len(title), 8, f"title too short: {title!r}")
        self.assertLessEqual(len(title), 120, f"title too long: {title!r}")

    def test_real_repo_scan_valid(self):
        """Scanning the real repo's docs/ should produce valid rows (smoke test)."""
        if not DOCS_DIR.is_dir():
            self.skipTest("real docs/ not accessible")
        # Use --json so no file is written; validate via validator
        proc = subprocess.run(
            [sys.executable, str(TOOL), "--json"],
            capture_output=True,
            text=True,
            cwd=str(REPO),
        )
        if proc.returncode == 2:
            self.skipTest("no CAPV3 docs in real repo (CI context)")
        self.assertEqual(proc.returncode, 0, f"stderr:\n{proc.stderr}")
        rows = [json.loads(line) for line in proc.stdout.splitlines() if line.strip()]
        self.assertGreater(len(rows), 0)
        for r in rows:
            self.assertEqual(r["type"], "next_loop_priority")


DOCS_DIR = REPO / "docs"

if __name__ == "__main__":
    unittest.main()
