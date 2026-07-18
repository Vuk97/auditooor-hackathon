"""test_agent_briefs_r39_coverage_check.py - unit tests for
tools/agent-briefs-r39-coverage-check.py.

Lane YYYY of V3 closeout iter15. Covers:
  - brief-with-canonical-class passes (anchored count > 0)
  - brief-with-orphan-class (declared as supported via the section) classified
    as "anchored" (the gate only inspects section presence, not the orphan-status
    of the class - that is R39's own gate at submission time)
  - brief-without-section is classified missing-section AND triggers exit-1
  - brief-with-TODO marker classified as acknowledged-todo and does NOT trigger
    exit-1 (an acknowledged gap is honest, not a silent failure)
  - --strict mode: TODO triggers exit-1
"""
from __future__ import annotations

import importlib.util
import json
import os
import pathlib
import subprocess
import sys
import tempfile
import textwrap
import unittest


REPO = pathlib.Path(__file__).resolve().parents[2]
TOOL_PATH = REPO / "tools" / "agent-briefs-r39-coverage-check.py"


def _load_module():
    spec = importlib.util.spec_from_file_location(
        "agent_briefs_r39_coverage_check", TOOL_PATH
    )
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


CHK = _load_module()


SECTION_BEGIN = "<!-- r39-anchor-section: begin -->"
SECTION_END = "<!-- r39-anchor-section: end -->"
SECTION_HEADER = "## Suggested attack_class (R39 anchor)"
TODO_MARKER = "<!-- TODO: classify (R39) -->"


def _brief_with_canonical(slug: str = "access_control"):
    return textwrap.dedent(f"""\
        # Agent Brief - {slug}

        Body.

        {SECTION_BEGIN}

        {SECTION_HEADER}

        | Class | Orphan-status | Rationale |
        |-------|---------------|-----------|
        | `missing-modifier-on-state-write` | canonical | brief focus |

        {SECTION_END}
        """)


def _brief_with_supported(slug: str = "fee_logic"):
    return textwrap.dedent(f"""\
        # Agent Brief - {slug}

        Body.

        {SECTION_BEGIN}

        {SECTION_HEADER}

        | Class | Orphan-status | Rationale |
        |-------|---------------|-----------|
        | `slippage` | supported-non-canonical | fee overcharge |

        {SECTION_END}
        """)


def _brief_with_todo(slug: str = "judge"):
    return textwrap.dedent(f"""\
        # Agent Brief - {slug}

        Body.

        {SECTION_BEGIN}

        {SECTION_HEADER}

        {TODO_MARKER}

        Status: TODO - per-dispatch classification required.

        {SECTION_END}
        """)


def _brief_without_section(slug: str = "random_old"):
    return textwrap.dedent(f"""\
        # Agent Brief - {slug}

        Body without any R39 section.
        """)


class ClassifyBriefTests(unittest.TestCase):
    def test_canonical_class_is_anchored(self):
        self.assertEqual(CHK.classify_brief(_brief_with_canonical()), CHK.STATUS_ANCHORED)

    def test_supported_non_canonical_class_is_anchored(self):
        # The gate only inspects section presence; the orphan-status of the
        # class itself is enforced by R39 at submission time, not here.
        self.assertEqual(CHK.classify_brief(_brief_with_supported()), CHK.STATUS_ANCHORED)

    def test_todo_marker_is_acknowledged_todo(self):
        self.assertEqual(CHK.classify_brief(_brief_with_todo()), CHK.STATUS_TODO)

    def test_missing_section_is_missing(self):
        self.assertEqual(CHK.classify_brief(_brief_without_section()), CHK.STATUS_MISSING)

    def test_header_alone_without_begin_end_still_counts(self):
        # A brief that has just the header (no HTML-comment delimiters) is still
        # considered anchored - the begin/end delimiters are a convenience for
        # idempotent re-edits, not the only valid form.
        content = f"# X\n\n{SECTION_HEADER}\n\n| class | status | rationale |\n|-|-|-|\n| `dos` | supported | x |\n"
        self.assertEqual(CHK.classify_brief(content), CHK.STATUS_ANCHORED)

    def test_header_with_todo_marker_classified_todo(self):
        content = f"# X\n\n{SECTION_HEADER}\n\n{TODO_MARKER}\n\nStatus: TODO.\n"
        self.assertEqual(CHK.classify_brief(content), CHK.STATUS_TODO)


class WalkBriefsTests(unittest.TestCase):
    def test_walk_empty_dir_returns_empty_list(self):
        with tempfile.TemporaryDirectory() as td:
            self.assertEqual(CHK.walk_briefs(td), [])

    def test_walk_skips_non_markdown(self):
        with tempfile.TemporaryDirectory() as td:
            p = pathlib.Path(td)
            (p / "brief_a.md").write_text(_brief_with_canonical())
            (p / "README.txt").write_text("ignore me")
            (p / "notes.json").write_text("{}")
            rows = CHK.walk_briefs(td)
            self.assertEqual(len(rows), 1)
            self.assertEqual(rows[0][0], "brief_a.md")

    def test_walk_sorts_by_filename(self):
        with tempfile.TemporaryDirectory() as td:
            p = pathlib.Path(td)
            (p / "z_last.md").write_text(_brief_with_canonical())
            (p / "a_first.md").write_text(_brief_with_todo())
            (p / "m_mid.md").write_text(_brief_without_section())
            rows = CHK.walk_briefs(td)
            self.assertEqual([f for f, _ in rows], ["a_first.md", "m_mid.md", "z_last.md"])

    def test_walk_missing_dir_returns_empty(self):
        self.assertEqual(CHK.walk_briefs("/tmp/non/existent/dir/xyz123"), [])


class BuildReportTests(unittest.TestCase):
    def test_all_anchored_report(self):
        rows = [("a.md", CHK.STATUS_ANCHORED), ("b.md", CHK.STATUS_ANCHORED)]
        r = CHK.build_report(rows)
        self.assertEqual(r["total_briefs"], 2)
        self.assertEqual(r["anchored_count"], 2)
        self.assertEqual(r["todo_count"], 0)
        self.assertEqual(r["missing_count"], 0)
        self.assertEqual(r["anchored_pct"], 100.0)
        self.assertEqual(r["exit_status"], "pass")

    def test_mixed_report_with_missing(self):
        rows = [
            ("a.md", CHK.STATUS_ANCHORED),
            ("b.md", CHK.STATUS_TODO),
            ("c.md", CHK.STATUS_MISSING),
        ]
        r = CHK.build_report(rows)
        self.assertEqual(r["total_briefs"], 3)
        self.assertEqual(r["anchored_count"], 1)
        self.assertEqual(r["todo_count"], 1)
        self.assertEqual(r["missing_count"], 1)
        self.assertAlmostEqual(r["anchored_pct"], 33.33, places=1)
        self.assertEqual(r["exit_status"], "fail-missing-section")

    def test_empty_input_zero_division_safe(self):
        r = CHK.build_report([])
        self.assertEqual(r["total_briefs"], 0)
        self.assertEqual(r["anchored_pct"], 0.0)
        self.assertEqual(r["exit_status"], "pass")  # no missing => no fail


class CliInvocationTests(unittest.TestCase):
    def _run(self, briefs_dir, extra=None):
        cmd = [sys.executable, str(TOOL_PATH), "--briefs-dir", briefs_dir, "--json"]
        if extra:
            cmd.extend(extra)
        return subprocess.run(cmd, capture_output=True, text=True)

    def test_cli_exits_zero_when_all_anchored(self):
        with tempfile.TemporaryDirectory() as td:
            (pathlib.Path(td) / "a.md").write_text(_brief_with_canonical())
            r = self._run(td)
            self.assertEqual(r.returncode, 0, r.stderr)
            data = json.loads(r.stdout)
            self.assertEqual(data["anchored_count"], 1)
            self.assertEqual(data["missing_count"], 0)

    def test_cli_exits_one_when_missing_section(self):
        with tempfile.TemporaryDirectory() as td:
            (pathlib.Path(td) / "a.md").write_text(_brief_without_section())
            r = self._run(td)
            self.assertEqual(r.returncode, 1)
            data = json.loads(r.stdout)
            self.assertEqual(data["missing_count"], 1)
            self.assertEqual(data["exit_status"], "fail-missing-section")

    def test_cli_exits_zero_when_only_todo_present(self):
        with tempfile.TemporaryDirectory() as td:
            (pathlib.Path(td) / "a.md").write_text(_brief_with_todo())
            r = self._run(td)
            self.assertEqual(r.returncode, 0)
            data = json.loads(r.stdout)
            self.assertEqual(data["todo_count"], 1)
            self.assertEqual(data["missing_count"], 0)

    def test_cli_strict_exits_one_when_todo_present(self):
        with tempfile.TemporaryDirectory() as td:
            (pathlib.Path(td) / "a.md").write_text(_brief_with_todo())
            r = self._run(td, extra=["--strict"])
            self.assertEqual(r.returncode, 1)

    def test_cli_strict_passes_when_all_anchored(self):
        with tempfile.TemporaryDirectory() as td:
            (pathlib.Path(td) / "a.md").write_text(_brief_with_canonical())
            (pathlib.Path(td) / "b.md").write_text(_brief_with_supported())
            r = self._run(td, extra=["--strict"])
            self.assertEqual(r.returncode, 0)


if __name__ == "__main__":
    unittest.main()
