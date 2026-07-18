"""Tests for R76 hallucination guard: read-only default + strict-promotion (PR2b)."""

from __future__ import annotations

import json
import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
TOOL = ROOT / "tools" / "r76-hallucination-guard.py"


def _make_scan_dir(tmp: Path) -> Path:
    scan = tmp / "mimo_harness_hyperbridge"
    scan.mkdir()
    sidecar = {
        "status": "ok",
        "task_id": "mimo-1",
        "workspace": "hyperbridge",
        "result": json.dumps({
            "applies_to_target": "yes",
            "confidence": "high",
            "file_line": "N/A conceptual pattern",
            "code_excerpt": "function imagined() external { return; }",
        }),
    }
    (scan / "mimo_0001.json").write_text(json.dumps(sidecar), encoding="utf-8")
    return scan


def _run(args, env_extra=None, timeout=60):
    env = os.environ.copy()
    if env_extra:
        env.update(env_extra)
    return subprocess.run(
        [sys.executable, str(TOOL), *args],
        capture_output=True, text=True, env=env, timeout=timeout,
    )


class TestR76ReadOnlyDefault(unittest.TestCase):
    def test_scan_mimo_dir_is_read_only_by_default(self) -> None:
        with tempfile.TemporaryDirectory(prefix="r76-ro-") as tmp_raw:
            tmp = Path(tmp_raw)
            scan = _make_scan_dir(tmp)
            derived = tmp / "derived"
            proc = _run(
                ["--scan-mimo-dir", str(scan), "--json"],
                env_extra={"AUDITOOOR_DERIVED_DIR": str(derived),
                           "AUDITOOOR_ANTI_PATTERNS_V2_DIR": str(tmp / "anti")},
            )
            self.assertEqual(proc.returncode, 1, proc.stderr)
            report = json.loads(proc.stdout)
            self.assertEqual(report["hallucination_count"], 1)
            self.assertTrue(report["read_only"])
            # Read-only: feedback NOT attempted, NO files written.
            self.assertFalse(report["feedback"]["attempted"])
            self.assertEqual(report["feedback"]["reason"], "read_only_default")
            self.assertFalse(derived.exists(),
                             "read-only scan must not write the derived dir")

    def test_write_feedback_restores_persistence(self) -> None:
        with tempfile.TemporaryDirectory(prefix="r76-wf-") as tmp_raw:
            tmp = Path(tmp_raw)
            scan = _make_scan_dir(tmp)
            proc = _run(
                ["--scan-mimo-dir", str(scan), "--write-feedback", "--json"],
                env_extra={"AUDITOOOR_DERIVED_DIR": str(tmp / "derived"),
                           "AUDITOOOR_ANTI_PATTERNS_V2_DIR": str(tmp / "anti")},
            )
            self.assertEqual(proc.returncode, 1, proc.stderr)
            report = json.loads(proc.stdout)
            self.assertEqual(report["hallucination_count"], 1)
            self.assertFalse(report["read_only"])
            self.assertTrue(report["feedback"]["attempted"])
            self.assertEqual(report["feedback"]["returncode"], 0)
            self.assertTrue((tmp / "derived" / "workspace_oos_extension_hyperbridge.json").is_file())

    def test_no_feedback_overrides_write_feedback(self) -> None:
        with tempfile.TemporaryDirectory(prefix="r76-nf-") as tmp_raw:
            tmp = Path(tmp_raw)
            scan = _make_scan_dir(tmp)
            derived = tmp / "derived"
            proc = _run(
                ["--scan-mimo-dir", str(scan), "--write-feedback",
                 "--no-feedback", "--json"],
                env_extra={"AUDITOOOR_DERIVED_DIR": str(derived),
                           "AUDITOOOR_ANTI_PATTERNS_V2_DIR": str(tmp / "anti")},
            )
            self.assertEqual(proc.returncode, 1, proc.stderr)
            report = json.loads(proc.stdout)
            self.assertFalse(report["feedback"]["attempted"])
            self.assertFalse(derived.exists())


class TestR76StrictPromotion(unittest.TestCase):
    def _draft(self, tmp: Path, body: str) -> Path:
        d = tmp / "draft.md"
        d.write_text(body, encoding="utf-8")
        return d

    def test_confirmed_without_excerpt_fails_strict(self) -> None:
        with tempfile.TemporaryDirectory(prefix="r76-sp1-") as tmp_raw:
            tmp = Path(tmp_raw)
            draft = self._draft(tmp, "verdict: CONFIRMED\nfile_line: src/A.sol:42\n")
            proc = _run([str(draft), "--strict-promotion", "--json"])
            self.assertEqual(proc.returncode, 1, proc.stderr)
            res = json.loads(proc.stdout)
            self.assertEqual(res["verdict"], "fail-no-code-excerpt")

    def test_confirmed_with_excerpt_no_workspace_fails_strict(self) -> None:
        with tempfile.TemporaryDirectory(prefix="r76-sp2-") as tmp_raw:
            tmp = Path(tmp_raw)
            draft = self._draft(
                tmp,
                "verdict: CONFIRMED\nfile_line: src/A.sol:42\n"
                "code_excerpt: function realThing() public { doStuff(); }\n",
            )
            proc = _run([str(draft), "--strict-promotion", "--json"])
            self.assertEqual(proc.returncode, 1, proc.stderr)
            res = json.loads(proc.stdout)
            self.assertEqual(res["verdict"], "fail-strict-no-workspace")

    def test_confirmed_with_grep_hit_passes_strict(self) -> None:
        with tempfile.TemporaryDirectory(prefix="r76-sp3-") as tmp_raw:
            tmp = Path(tmp_raw)
            ws = tmp / "ws"
            ws.mkdir()
            (ws / "A.sol").write_text(
                "contract A { function realThing() public { doStuff(); } }\n",
                encoding="utf-8",
            )
            draft = self._draft(
                tmp,
                "verdict: CONFIRMED\nfile_line: A.sol:1\n"
                "code_excerpt: function realThing() public { doStuff(); }\n",
            )
            proc = _run([str(draft), "--strict-promotion",
                         "--workspace", str(ws), "--json"])
            self.assertEqual(proc.returncode, 0, proc.stderr)
            res = json.loads(proc.stdout)
            self.assertEqual(res["verdict"], "pass-verified")

    def test_non_strict_confirmed_no_excerpt_still_passes(self) -> None:
        # Without --strict-promotion, the legacy lenient behavior holds.
        with tempfile.TemporaryDirectory(prefix="r76-sp4-") as tmp_raw:
            tmp = Path(tmp_raw)
            draft = self._draft(tmp, "verdict: CONFIRMED\nfile_line: src/A.sol:42\n")
            proc = _run([str(draft), "--json"])
            self.assertEqual(proc.returncode, 0, proc.stderr)
            res = json.loads(proc.stdout)
            self.assertEqual(res["verdict"], "pass-verified")


if __name__ == "__main__":
    unittest.main()
