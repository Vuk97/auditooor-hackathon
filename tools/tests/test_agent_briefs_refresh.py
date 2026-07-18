"""test_agent_briefs_refresh.py - unit tests for tools/agent-briefs-refresh.py."""
from __future__ import annotations

import datetime as dt
import importlib.util
import json
import os
import pathlib
import subprocess
import sys
import tempfile
import textwrap
import time
import unittest
from typing import Any


REPO = pathlib.Path(__file__).resolve().parents[2]
TOOL_PATH = REPO / "tools" / "agent-briefs-refresh.py"


def _load_module():
    spec = importlib.util.spec_from_file_location("agent_briefs_refresh", TOOL_PATH)
    assert spec is not None and spec.loader is not None, "cannot load tool spec"
    module = importlib.util.module_from_spec(spec)
    # Register in sys.modules so dataclasses' module-lookup works under py3.14+
    sys.modules["agent_briefs_refresh"] = module
    spec.loader.exec_module(module)
    return module


ABR = _load_module()


def _set_mtime_days_ago(path: pathlib.Path, days: float) -> None:
    """Backdate a file's mtime by `days` days."""
    target = time.time() - days * 86400.0
    os.utime(path, (target, target))


def _make_brief(briefs_dir: pathlib.Path, name: str, age_days: float, body: str = "x") -> pathlib.Path:
    """Create a brief at briefs_dir/<name> backdated by age_days."""
    briefs_dir.mkdir(parents=True, exist_ok=True)
    p = briefs_dir / name
    p.write_text(body, encoding="utf-8")
    _set_mtime_days_ago(p, age_days)
    return p


class ClassifyTests(unittest.TestCase):
    def test_static_persona_brief_classified_static(self):
        self.assertEqual(ABR._classify("access_control.md"), "static")
        self.assertEqual(ABR._classify("red_team.md"), "static")
        self.assertEqual(ABR._classify("judge.md"), "static")

    def test_detector_brief_classified_detector(self):
        self.assertEqual(ABR._classify("detector-reentrancy-guard.md"), "detector")
        self.assertEqual(ABR._classify("detector-foo-bar.md"), "detector")

    def test_unknown_brief_classified_unknown(self):
        self.assertEqual(ABR._classify("random_brief.md"), "unknown")


class BucketTests(unittest.TestCase):
    def test_fresh_under_skip_threshold(self):
        self.assertEqual(ABR._bucket(0.4, fresh_skip=1, warn=7, fail=14), "fresh")

    def test_warn_band(self):
        self.assertEqual(ABR._bucket(8.0, fresh_skip=1, warn=7, fail=14), "warn")

    def test_fail_at_threshold(self):
        self.assertEqual(ABR._bucket(14.0, fresh_skip=1, warn=7, fail=14), "fail")

    def test_fail_above_threshold(self):
        self.assertEqual(ABR._bucket(30.0, fresh_skip=1, warn=7, fail=14), "fail")

    def test_between_skip_and_warn_treated_fresh(self):
        self.assertEqual(ABR._bucket(3.0, fresh_skip=1, warn=7, fail=14), "fresh")


class AuditFreshTests(unittest.TestCase):
    def test_fresh_brief_skipped(self):
        with tempfile.TemporaryDirectory() as tmp:
            tmp_path = pathlib.Path(tmp)
            _make_brief(tmp_path, "red_team.md", age_days=0.1)
            statuses = ABR.audit_briefs(tmp_path, attempt_regenerate=False)
            self.assertEqual(len(statuses), 1)
            s = statuses[0]
            self.assertEqual(s.bucket, "fresh")
            self.assertFalse(s.regenerated)
            self.assertIn("fresh", (s.skipped_reason or ""))


class AuditStaleStaticTests(unittest.TestCase):
    def test_stale_static_brief_warn_not_regenerated(self):
        with tempfile.TemporaryDirectory() as tmp:
            tmp_path = pathlib.Path(tmp)
            _make_brief(tmp_path, "red_team.md", age_days=10.0)
            statuses = ABR.audit_briefs(tmp_path, attempt_regenerate=True)
            s = statuses[0]
            self.assertEqual(s.category, "static")
            self.assertEqual(s.bucket, "warn")
            self.assertFalse(s.regenerated)
            self.assertIn("static-persona", (s.skipped_reason or ""))

    def test_very_stale_static_brief_fail(self):
        with tempfile.TemporaryDirectory() as tmp:
            tmp_path = pathlib.Path(tmp)
            _make_brief(tmp_path, "blue_team.md", age_days=21.0)
            statuses = ABR.audit_briefs(tmp_path, attempt_regenerate=True)
            s = statuses[0]
            self.assertEqual(s.bucket, "fail")
            self.assertFalse(s.regenerated)


class AuditMissingGeneratorTests(unittest.TestCase):
    def test_detector_brief_no_workspace_reports_error_gracefully(self):
        """Detector brief with no workspace: regenerate-attempt records honest error."""
        with tempfile.TemporaryDirectory() as tmp:
            tmp_path = pathlib.Path(tmp)
            _make_brief(tmp_path, "detector-foo.md", age_days=10.0)
            statuses = ABR.audit_briefs(tmp_path, workspace=None, attempt_regenerate=True)
            s = statuses[0]
            self.assertEqual(s.category, "detector")
            self.assertEqual(s.bucket, "warn")
            self.assertFalse(s.regenerated)
            self.assertIsNotNone(s.regenerate_error)
            self.assertIn("workspace", s.regenerate_error)

    def test_detector_brief_no_queue_reports_error_gracefully(self):
        """Detector brief with workspace but no task queue: honest error."""
        with tempfile.TemporaryDirectory() as tmp:
            tmp_path = pathlib.Path(tmp)
            briefs_dir = tmp_path / "briefs"
            workspace = tmp_path / "ws"
            workspace.mkdir()
            _make_brief(briefs_dir, "detector-foo.md", age_days=10.0)
            statuses = ABR.audit_briefs(
                briefs_dir, workspace=workspace, attempt_regenerate=True
            )
            s = statuses[0]
            self.assertFalse(s.regenerated)
            self.assertIsNotNone(s.regenerate_error)
            self.assertIn("queue", s.regenerate_error)


class AuditAttemptRegenerateOffTests(unittest.TestCase):
    def test_no_regenerate_flag_skips_regeneration(self):
        with tempfile.TemporaryDirectory() as tmp:
            tmp_path = pathlib.Path(tmp)
            _make_brief(tmp_path, "detector-bar.md", age_days=10.0)
            statuses = ABR.audit_briefs(tmp_path, attempt_regenerate=False)
            s = statuses[0]
            self.assertFalse(s.regenerated)
            # When attempt_regenerate=False, no regenerate_error is set
            # because the regen path was never invoked.
            self.assertIsNone(s.regenerate_error)


class IdempotencyTests(unittest.TestCase):
    def test_audit_is_idempotent_for_fresh_briefs(self):
        """Running audit twice in a row produces the same verdicts."""
        with tempfile.TemporaryDirectory() as tmp:
            tmp_path = pathlib.Path(tmp)
            _make_brief(tmp_path, "red_team.md", age_days=0.1)
            _make_brief(tmp_path, "blue_team.md", age_days=10.0)
            first = ABR.audit_briefs(tmp_path, attempt_regenerate=False)
            second = ABR.audit_briefs(tmp_path, attempt_regenerate=False)
            self.assertEqual(len(first), len(second))
            for a, b in zip(first, second):
                self.assertEqual(a.name, b.name)
                self.assertEqual(a.bucket, b.bucket)
                self.assertEqual(a.category, b.category)

    def test_audit_does_not_modify_static_briefs(self):
        """Audit pass must NOT touch static briefs' contents or mtime."""
        with tempfile.TemporaryDirectory() as tmp:
            tmp_path = pathlib.Path(tmp)
            p = _make_brief(tmp_path, "judge.md", age_days=10.0, body="hello world")
            mtime_before = p.stat().st_mtime
            body_before = p.read_text(encoding="utf-8")
            ABR.audit_briefs(tmp_path, attempt_regenerate=True)
            self.assertEqual(p.stat().st_mtime, mtime_before)
            self.assertEqual(p.read_text(encoding="utf-8"), body_before)


class SummaryTests(unittest.TestCase):
    def test_summary_counts(self):
        with tempfile.TemporaryDirectory() as tmp:
            tmp_path = pathlib.Path(tmp)
            _make_brief(tmp_path, "red_team.md", age_days=0.1)        # fresh static
            _make_brief(tmp_path, "blue_team.md", age_days=10.0)      # warn static
            _make_brief(tmp_path, "judge.md", age_days=20.0)          # fail static
            _make_brief(tmp_path, "detector-x.md", age_days=10.0)     # warn detector
            statuses = ABR.audit_briefs(tmp_path, attempt_regenerate=False)
            summary = ABR.summarize(statuses)
            self.assertEqual(summary["total_briefs"], 4)
            self.assertEqual(summary["by_bucket"]["fresh"], 1)
            self.assertEqual(summary["by_bucket"]["warn"], 2)
            self.assertEqual(summary["by_bucket"]["fail"], 1)
            self.assertEqual(summary["by_category"]["static"], 3)
            self.assertEqual(summary["by_category"]["detector"], 1)
            self.assertIn("judge.md", summary["fail_briefs"])


class CLIExitCodeTests(unittest.TestCase):
    """Exit-code contract: 0 ok, 1 fail-band, 2 input-error, 3 strict-warn."""

    def _run(self, *extra_args: str, briefs_dir: pathlib.Path) -> subprocess.CompletedProcess:
        cmd = [
            sys.executable,
            str(TOOL_PATH),
            "--briefs-dir",
            str(briefs_dir),
            "--no-regenerate",
            *extra_args,
        ]
        return subprocess.run(cmd, capture_output=True, text=True, timeout=30)

    def test_all_fresh_returns_zero(self):
        with tempfile.TemporaryDirectory() as tmp:
            tmp_path = pathlib.Path(tmp)
            _make_brief(tmp_path, "red_team.md", age_days=0.1)
            r = self._run(briefs_dir=tmp_path)
            self.assertEqual(r.returncode, 0, msg=r.stderr + r.stdout)

    def test_fail_band_returns_one(self):
        with tempfile.TemporaryDirectory() as tmp:
            tmp_path = pathlib.Path(tmp)
            _make_brief(tmp_path, "red_team.md", age_days=21.0)
            r = self._run(briefs_dir=tmp_path)
            self.assertEqual(r.returncode, 1, msg=r.stderr + r.stdout)

    def test_strict_warn_returns_three(self):
        with tempfile.TemporaryDirectory() as tmp:
            tmp_path = pathlib.Path(tmp)
            _make_brief(tmp_path, "red_team.md", age_days=10.0)
            r = self._run("--strict", briefs_dir=tmp_path)
            self.assertEqual(r.returncode, 3, msg=r.stderr + r.stdout)

    def test_non_strict_warn_returns_zero(self):
        with tempfile.TemporaryDirectory() as tmp:
            tmp_path = pathlib.Path(tmp)
            _make_brief(tmp_path, "red_team.md", age_days=10.0)
            r = self._run(briefs_dir=tmp_path)
            self.assertEqual(r.returncode, 0, msg=r.stderr + r.stdout)

    def test_missing_briefs_dir_returns_two(self):
        with tempfile.TemporaryDirectory() as tmp:
            missing = pathlib.Path(tmp) / "does-not-exist"
            r = self._run(briefs_dir=missing)
            self.assertEqual(r.returncode, 2, msg=r.stderr + r.stdout)

    def test_json_output_is_valid_json(self):
        with tempfile.TemporaryDirectory() as tmp:
            tmp_path = pathlib.Path(tmp)
            _make_brief(tmp_path, "red_team.md", age_days=0.1)
            r = self._run("--json", briefs_dir=tmp_path)
            self.assertEqual(r.returncode, 0, msg=r.stderr)
            payload = json.loads(r.stdout)
            self.assertEqual(payload["schema"], ABR.SCHEMA)
            self.assertEqual(payload["summary"]["total_briefs"], 1)


class IntegrationLiveBriefsTests(unittest.TestCase):
    """Read-only check that the live agent_briefs/ inventory is parseable.

    Does NOT modify the live directory. Verifies the tool can audit it without
    crashing and returns sensible category counts.
    """

    def test_live_briefs_dir_audits_cleanly(self):
        if not ABR.BRIEFS_DIR.is_dir():
            self.skipTest("agent_briefs/ not present in repo")
        statuses = ABR.audit_briefs(ABR.BRIEFS_DIR, attempt_regenerate=False)
        self.assertGreater(len(statuses), 0, "expected >=1 brief in live dir")
        summary = ABR.summarize(statuses)
        # At least one of the well-known static personas must classify correctly.
        names = {s.name for s in statuses}
        self.assertTrue(
            any(n in ABR.STATIC_PERSONA_BRIEFS for n in names),
            f"expected at least one known static persona; got names={names}",
        )


if __name__ == "__main__":
    unittest.main(verbosity=2)
